#include "group_manager.h"
phmap::flat_hash_map<uint64_t, Group*> groups;

std::shared_mutex groups_mtx;

SetParentCallbacks set_parent_callbacks;
SetOptionGroupCallbacks set_option_group_callbacks;
GroupPermissionCallbacks group_permission_callbacks;
GroupCreateCallbacks group_create_callbacks;
GroupDeleteCallbacks group_delete_callbacks;

LoadGroupsCallbacks load_groups_callbacks;

PLUGIFY_WARN_PUSH()

#if defined(__clang__)
PLUGIFY_WARN_IGNORE ("-Wreturn-type-c-linkage")
#elif defined(_MSC_VER)
PLUGIFY_WARN_IGNORE (4190)
#endif

/**
 * @brief Set parent group for child group
 *
 * @param pluginID Identifier of the plugin that calls the method.
 * @param childName Child group name
 * @param parentName Parent group name to set
 * @return Success, ChildGroupNotFound, ParentGroupNotFound
 */
extern "C" PLUGIN_API Status SetParent(const int64_t pluginID, const plg::string& childName,
                                       const plg::string& parentName)
{
    const uint64_t hash1 = XXH3_64bits(childName.data(), childName.size());
    const uint64_t hash2 = XXH3_64bits(parentName.data(), parentName.size());
    std::unique_lock lock(groups_mtx);
    const auto it1 = groups.find(hash1);
    const auto it2 = groups.find(hash2);

	const bool empty_group = childName.empty();

    if (it1 == groups.end() && !empty_group)
    	return Status::ChildGroupNotFound;
    if (it2 == groups.end())
        return Status::ParentGroupNotFound;

    it1->second->_parent = empty_group ? nullptr : it2->second;
    {
        std::shared_lock lock2(set_parent_callbacks._lock);
        for (const SetParentCallback cb : set_parent_callbacks._callbacks)
            cb(pluginID, childName, parentName);
    }
    return Status::Success;
}

/**
 * @brief Get parent of requested group
 *
 * @param groupName Group name
 * @param parentName Parent name
 * @return Success, ChildGroupNotFound, ParentGroupNotFound
 */
extern "C" PLUGIN_API Status GetParent(const plg::string& groupName, plg::string& parentName)
{
    const uint64_t hash = XXH3_64bits(groupName.data(), groupName.size());
    std::shared_lock lock(groups_mtx);
    const auto it = groups.find(hash);

    if (it == groups.end())
        return Status::ChildGroupNotFound;
    if (!it->second->_parent)
        return Status::ParentGroupNotFound;
    parentName = it->second->_parent->_name;
    return Status::Success;
}

/**
 * @brief Get permissions of group
 *
 * @param name Group name
 * @param perms Permissions
 * @return Success, GroupNotFound
 */
extern "C" PLUGIN_API Status DumpPermissionsGroup(const plg::string& name, plg::vector<plg::string>& perms)
{
    const uint64_t hash = XXH3_64bits(name.data(), name.size());
    std::shared_lock lock(groups_mtx);
    const auto v = groups.find(hash);
    if (v == groups.end())
        return Status::ChildGroupNotFound;

    perms = Node::dumpNode(v->second->_nodes);

    return Status::Success;
}

/**
 * @brief Get all created groups
 *
 * @return Array of groups
 */
extern "C" PLUGIN_API plg::vector<plg::string> GetAllGroups()
{
    std::shared_lock lock(groups_mtx);

    plg::vector<plg::string> lgroups;
    lgroups.reserve(groups.size());
    for (const auto& [kv, vv] : groups)
        lgroups.push_back(vv->_name);

    return lgroups;
}

/**
 * @brief Check if a group has a specific permission.
 *
 * @param name Group name.
 * @param perm Permission line.
 * @param exact Checking permission with ignoring wildcards (pass 'false' for default behavior)
 * @return Allow, Disallow, PermNotFound, GroupNotFound
 */
extern "C" PLUGIN_API Status HasPermissionGroupExtended(const plg::string& name, const plg::string& perm, const bool exact)
{
    const uint64_t hash = XXH3_64bits(name.data(), name.size());
    std::shared_lock lock(groups_mtx);
    const auto it = groups.find(hash);
    if (it == groups.end())
        return Status::GroupNotFound;

    bool w_wildcard;
    Status status = it->second->hasPermission(perm, exact, w_wildcard);
    if (exact && isWildcard(perm) != w_wildcard)
        return Status::PermNotFound;
    return status;
}

/**
 * @brief Check if a group has a specific permission.
 *
 * @param name Group name.
 * @param perm Permission line.
 * @return Allow, Disallow, PermNotFound, GroupNotFound
 */
extern "C" PLUGIN_API Status HasPermissionGroup(const plg::string& name, const plg::string& perm)
{
    return HasPermissionGroupExtended(name, perm, false);
}

/**
 * @brief Check if parent_name is a parent group for child_name.
 *
 * @param childName Child group name.
 * @param parentName Parent group name to check.
 * @return Allow, Disallow, ChildGroupNotFound, ParentGroupNotFound
 */
extern "C" PLUGIN_API Status HasParentGroup(const plg::string& childName, const plg::string& parentName)
{
    const uint64_t hash1 = XXH3_64bits(childName.data(), childName.size());
    const uint64_t hash2 = XXH3_64bits(parentName.data(), parentName.size());
    std::shared_lock lock(groups_mtx);
    const auto it1 = groups.find(hash1);
    const auto it2 = groups.find(hash2);
    if (it1 == groups.end())
        return Status::ChildGroupNotFound;
    if (it2 == groups.end())
        return Status::ParentGroupNotFound;

    const Group* g1 = it1->second;
    const Group* g2 = it2->second;
    while (g1)
    {
        if (g1->_parent == g2) return Status::Allow;
        g1 = g1->_parent;
    }
    return Status::Disallow;
}

/**
 * @brief Get the priority of a group.
 *
 * @param groupName Group name.
 * @param priority Priority
 * @return Success, GroupNotFound
 */
extern "C" PLUGIN_API Status GetPriorityGroup(const plg::string& groupName, int& priority)
{
    const uint64_t hash = XXH3_64bits(groupName.data(), groupName.size());
    std::shared_lock lock(groups_mtx);
    const auto it = groups.find(hash);
    if (it == groups.end())
        return Status::GroupNotFound;
    priority = it->second->_priority;
    return Status::Success;
}

/**
 * @brief Add a permission to a group.
 *
 * @param pluginID Identifier of the plugin that calls the method.
 * @param name Group name.
 * @param perm Permission line.
 * @param dontBroadcast If set to `true`, suppresses dispatching of the permission change event to registered GroupPermission listeners. The permission is still applied internally.
 * @return Success, GroupNotFound, PermAlreadyGranted
 */
extern "C" PLUGIN_API Status AddPermissionGroup(const int64_t pluginID, const plg::string& name,
                                                const plg::string& perm, const bool dontBroadcast)
{
    const uint64_t hash = XXH3_64bits(name.data(), name.size());
    std::unique_lock lock1(groups_mtx);
    const auto it = groups.find(hash);
    if (it == groups.end())
        return Status::GroupNotFound;

    const bool denied = perm.starts_with('-');
    bool w_wildcard;
    const Status oldState = it->second->hasPermission(perm, true, w_wildcard);
    const bool diff = !((denied && oldState == Status::Disallow) || (!denied && oldState == Status::Allow));

	bool replaceToWC = false;
	Action act = Action::Add;

    if (oldState != Status::PermNotFound) // Node is existed - check if user want to rewrite wildcard
    {
    	if (diff)
    		return Status::PermAlreadyGranted;

    	if (!isWildcard(perm))
    	{
    		if (w_wildcard)
    			return Status::PermAlreadyGranted;
    	}
    	else if (!w_wildcard)
    	{
    		replaceToWC = true;
    	}

    	act = Action::Replace;
    }

	plg::vector<plg::string> deleted_perms;

	if (!dontBroadcast) {
		if (replaceToWC)
			act = Action::ReplaceToWC;
		const plg::string prm = denied ? perm.substr(1) : perm;
		std::unique_lock lock2(users_mtx); // Need to eliminate race in user->group permissions check
		it->second->_nodes.addPerm(perm);
		{
			std::shared_lock lock3(group_permission_callbacks._lock);
			for (const GroupPermissionCallback cb : group_permission_callbacks._callbacks)
				cb(pluginID, act, name, perm, oldState, denied ? Status::Disallow : Status::Allow);
		}
	}
    return Status::Success;
}

extern "C" PLUGIN_API Status SetPermissionGroup(const int64_t pluginID, const plg::string& name,
												const plg::string& perm, const bool dontBroadcast)
{
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::unique_lock lock1(groups_mtx);
	const auto it = groups.find(hash);
	if (it == groups.end())
		return Status::GroupNotFound;

	const bool denied = perm.starts_with('-');
	bool w_wildcard;
	const Status oldState = it->second->hasPermission(perm, true, w_wildcard);
	bool diff = !((denied && oldState == Status::Disallow) || (!denied && oldState == Status::Allow));

	bool replaceToWC = false;
	Action act = Action::Add;
	if (oldState != Status::PermNotFound) // Node is existing - check if user want to rewrite wildcard
	{
		if (!isWildcard(perm))
		{
			if (w_wildcard)
				return Status::PermAlreadyGranted;
		}
		else if (!w_wildcard)
		{
			replaceToWC = true;
			diff = true;
		}
		act = Action::Replace;
	}

	if (!diff)
		return Status::PermAlreadyGranted;

	if (!dontBroadcast) {
		if (replaceToWC)
			act = Action::ReplaceToWC;
		const plg::string prm = denied ? perm.substr(1) : perm;
		std::unique_lock lock2(users_mtx); // Need to eliminate race in user->group permissions check
		it->second->_nodes.addPerm(perm);
		{
			std::shared_lock lock3(group_permission_callbacks._lock);
			for (const GroupPermissionCallback cb : group_permission_callbacks._callbacks)
				cb(pluginID, act, name, perm, oldState, denied ? Status::Disallow : Status::Allow);
		}
	}

	return Status::Success;
}

/**
 * @brief Remove a permission from a group.
 *
 * @param pluginID Identifier of the plugin that calls the method.
 * @param name Group name.
 * @param perm Permission line.
 * @param recursiveDeletion Delete all nested perms.
 * @return Success, GroupNotFound, PermNotFound
 */
extern "C" PLUGIN_API Status RemovePermissionGroup(const int64_t pluginID, const plg::string& name,
                                                   const plg::string& perm, const bool recursiveDeletion)
{
    const uint64_t hash = XXH3_64bits(name.data(), name.size());
    std::unique_lock lock1(groups_mtx);
    const auto it = groups.find(hash);
    if (it == groups.end())
        return Status::GroupNotFound;

	bool w_wildcard;
	const auto oldState = it->second->hasPermission(perm, true, w_wildcard);
	if (oldState == Status::PermNotFound)
		return Status::PermNotFound;

    plg::vector<plg::string> deleted_perms;

    std::unique_lock lock2(users_mtx); // Need to eliminate race in user->group permissions check

	const bool ret = it->second->_nodes.deletePerm(perm, recursiveDeletion, deleted_perms);
	if (!ret)
		return Status::PermNotFound;
    {
        std::shared_lock lock3(group_permission_callbacks._lock);
        for (const GroupPermissionCallback cb : group_permission_callbacks._callbacks)
            for (const plg::string& s : deleted_perms)
                cb(pluginID, Action::Remove, s, perm, oldState, Status::PermNotFound);
    }
    return Status::Success;
}

/**
 * @brief Get an option value for a group.
 *
 * @param groupName Group name
 * @param optionName Option name
 * @param value Option value
 * @return Success, OptionNotFound, GroupNotFound
 */
extern "C" PLUGIN_API Status GetOptionGroup(const plg::string& groupName, const plg::string& optionName,
                                            plg::any& value)
{
    const uint64_t hash = XXH3_64bits(groupName.data(), groupName.size());
    std::shared_lock lock(groups_mtx);
    const auto v = groups.find(hash);
    if (v == groups.end())
        return Status::GroupNotFound;

    Group* g = v->second;
    while (g != nullptr)
    {
        const auto val = g->options.find(optionName);
        if (val == g->options.end())
        {
            g = g->_parent;
            continue;
        }
        value = val->second;
        return Status::Success;
    }
    return Status::OptionNotFound;
}

/**
 * @brief Set an option value for a group.
 *
 * @param pluginID Identifier of the plugin that calls the method.
 * @param groupName Group name
 * @param optionName Option name
 * @param value Option value.
 * @return Success, GroupNotFound
 */
extern "C" PLUGIN_API Status SetOptionGroup(const int64_t pluginID, const plg::string& groupName,
                                            const plg::string& optionName, const plg::any& value)
{
    const uint64_t hash = XXH3_64bits(groupName.data(), groupName.size());
    std::unique_lock lock(groups_mtx);
    const auto v = groups.find(hash);
    if (v == groups.end())
        return Status::GroupNotFound;

    std::unique_lock lock2(users_mtx); // Need to eliminate race in user->group permissions check
    {
        std::shared_lock lock3(set_option_group_callbacks._lock);
        for (const SetOptionGroupCallback cb : set_option_group_callbacks._callbacks)
            cb(pluginID, groupName, optionName, value);
    }
    v->second->options[optionName] = value;
    return Status::Success;
}

/**
 * @brief Get all options from group.
 *
 * @param groupName Group name
 * @param optionNames Array of option names
 * @param values Array of option values
 * @return Success, GroupNotFound
 */

extern "C" PLUGIN_API Status GetAllOptionsGroup(const plg::string& groupName, plg::vector<plg::string>& optionNames,
                                                plg::vector<plg::any>& values)
{
    const uint64_t hash = XXH3_64bits(groupName.data(), groupName.size());
    std::shared_lock lock(groups_mtx);
    const auto v = groups.find(hash);
    if (v == groups.end())
        return Status::GroupNotFound;

    optionNames.clear();
    values.clear();

    for (const auto& [kv, vv] : v->second->options)
    {
        optionNames.push_back(kv);
        values.push_back(vv);
    }

    return Status::Success;
}

/**
 * @brief Create a new group.
 *
 * @param pluginID Identifier of the plugin that calls the method.
 * @param name Group name.
 * @param perms Array of permission lines.
 * @param priority Group priority.
 * @param parent Parent group name.
 * @return Success, GroupAlreadyExist, ParentGroupNotFound
 */
extern "C" PLUGIN_API Status CreateGroup(const int64_t pluginID, const plg::string& name,
                                         const plg::vector<plg::string>& perms, const int priority,
                                         const plg::string& parent)
{
    const uint64_t hash = XXH3_64bits(name.data(), name.size());
    std::unique_lock lock(groups_mtx);
    if (groups.contains(hash))
        return Status::GroupAlreadyExist;
    Group* parentGroup = nullptr;
    if (!parent.empty())
    {
        parentGroup = GetGroup(parent);
        if (!parentGroup) return Status::ParentGroupNotFound;
    }

    auto* group = new Group(perms, name, priority, parentGroup);
    groups.try_emplace(hash, group);
    {
        std::shared_lock lock2(group_create_callbacks._lock);
        for (const GroupCreateCallback cb : group_create_callbacks._callbacks)
            cb(pluginID, name, perms, priority, parent);
    }
    return Status::Success;
}

/**
 * @brief Delete a group.
 *
 * @param pluginID Identifier of the plugin that calls the method.
 * @param name Group name.
 * @return Success if deleted; GroupNotFound if group not found.
 */
extern "C" PLUGIN_API Status DeleteGroup(const int64_t pluginID, const plg::string& name)
{
    const uint64_t hash = XXH3_64bits(name.data(), name.size());
    std::unique_lock lock(groups_mtx);
    const auto it = groups.find(hash);
    if (it == groups.end())
        return Status::GroupNotFound;

    {
        std::shared_lock lock2(group_delete_callbacks._lock);
        for (const GroupDeleteCallback cb : group_delete_callbacks._callbacks)
            cb(pluginID, name);
    }
    const Group* req_group = it->second;
    groups.erase(it);

    // Cleanup parent references in other groups
    for (Group* value : groups | std::views::values)
    {
        Group* cur_group = value;
        while (cur_group)
        {
            if (cur_group->_parent == req_group)
            {
                cur_group->_parent = nullptr;
                break;
            }
            cur_group = cur_group->_parent;
        }
    }

    GroupManager_Callback(req_group); // Delete group in users
    delete req_group;
    return Status::Success;
}

/**
 * @brief Check if a group exists.
 *
 * @param name Group name.
 * @return True if group exists, false otherwise.
 */
extern "C" PLUGIN_API bool GroupExists(const plg::string& name)
{
    const uint64_t hash = XXH3_64bits(name.data(), name.size());
    std::unique_lock lock(groups_mtx);
    const auto v = groups.find(hash);
    return v != groups.end();
}

/**
 * @brief Dispatches a request to load server groups for a plugin.
 *
 * This function notifies all registered LoadGroups callbacks that
 * group data for the specified plugin must be loaded.
 * It does not perform any storage operations itself — the actual
 * loading logic is handled by subscribed extensions (e.g., database providers).
 *
 * Thread-safe: acquires a shared lock while iterating over callbacks.
 *
 * @param pluginID Identifier of the plugin that calls the method.
 */
extern "C" PLUGIN_API void LoadGroups(const int64_t pluginID)
{
    std::shared_lock lock2(load_groups_callbacks._lock);
    for (const LoadGroupsCallback cb : load_groups_callbacks._callbacks)
        cb(pluginID);
}

/**
 * @brief Register listener on LoadGroups event.
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnLoadGroups_Register(LoadGroupsCallback callback)
{
    std::unique_lock lock(load_groups_callbacks._lock);
    auto ret = load_groups_callbacks._callbacks.insert(callback);
    return ret.second ? Status::Success : Status::CallbackAlreadyExist;
}

/**
 * @brief Unregister listener on LoadGroups event.
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnLoadGroups_Unregister(LoadGroupsCallback callback)
{
    std::unique_lock lock(load_groups_callbacks._lock);
    const size_t ret = load_groups_callbacks._callbacks.erase(callback);
    return ret > 0 ? Status::Success : Status::CallbackNotFound;
}

/**
 * @brief Register listener on group parent changing
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnGroupSetParent_Register(SetParentCallback callback)
{
    std::unique_lock lock(set_parent_callbacks._lock);
    auto ret = set_parent_callbacks._callbacks.insert(callback);
    return ret.second ? Status::Success : Status::CallbackAlreadyExist;
}

/**
 * @brief Unregister listener on group parent changing
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnGroupSetParent_Unregister(SetParentCallback callback)
{
    std::unique_lock lock(set_parent_callbacks._lock);
    const size_t ret = set_parent_callbacks._callbacks.erase(callback);
    return ret > 0 ? Status::Success : Status::CallbackNotFound;
}

/**
 * @brief Register listener on group option sets
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnGroupSetOption_Register(SetOptionGroupCallback callback)
{
    std::unique_lock lock(set_option_group_callbacks._lock);
    auto ret = set_option_group_callbacks._callbacks.insert(callback);
    return ret.second ? Status::Success : Status::CallbackAlreadyExist;
}

/**
 * @brief Unregister listener on group option sets
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnGroupSetOption_Unregister(SetOptionGroupCallback callback)
{
    std::unique_lock lock(set_option_group_callbacks._lock);
    const size_t ret = set_option_group_callbacks._callbacks.erase(callback);
    return ret > 0 ? Status::Success : Status::CallbackNotFound;
}

/**
 * @brief Register listener on group permissions add/remove
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnGroupPermissionChange_Register(GroupPermissionCallback callback)
{
    std::unique_lock lock(group_permission_callbacks._lock);
    auto ret = group_permission_callbacks._callbacks.insert(callback);
    return ret.second ? Status::Success : Status::CallbackAlreadyExist;
}

/**
 * @brief Unregister listener on group permissions add/remove
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnGroupPermissionChange_Unregister(GroupPermissionCallback callback)
{
    std::unique_lock lock(group_permission_callbacks._lock);
    const size_t ret = group_permission_callbacks._callbacks.erase(callback);
    return ret > 0 ? Status::Success : Status::CallbackNotFound;
}

/**
 * @brief Register listener on group creation
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnGroupCreate_Register(GroupCreateCallback callback)
{
    std::unique_lock lock(group_create_callbacks._lock);
    auto ret = group_create_callbacks._callbacks.insert(callback);
    return ret.second ? Status::Success : Status::CallbackAlreadyExist;
}

/**
 * @brief Unregister listener on group creation
 *
 * @param callback Listener
 * @return
 */
extern "C" PLUGIN_API Status OnGroupCreate_Unregister(GroupCreateCallback callback)
{
    std::unique_lock lock(group_create_callbacks._lock);
    const size_t ret = group_create_callbacks._callbacks.erase(callback);
    return ret > 0 ? Status::Success : Status::CallbackNotFound;
}

/**
 * @brief Register listener on group deletion
 *
 * @param callback Listener
 * @return
 */
extern "C" PLUGIN_API Status OnGroupDelete_Register(GroupDeleteCallback callback)
{
    std::unique_lock lock(group_delete_callbacks._lock);
    auto ret = group_delete_callbacks._callbacks.insert(callback);
    return ret.second ? Status::Success : Status::CallbackAlreadyExist;
}

/**
 * @brief Unregister listener on group deletion
 *
 * @param callback Listener
 * @return
 */
extern "C" PLUGIN_API Status OnGroupDelete_Unregister(GroupDeleteCallback callback)
{
    std::unique_lock lock(group_delete_callbacks._lock);
    const size_t ret = group_delete_callbacks._callbacks.erase(callback);
    return ret > 0 ? Status::Success : Status::CallbackNotFound;
}

PLUGIFY_WARN_POP()
