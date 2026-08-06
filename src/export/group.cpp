#include "core/group_manager.hpp"
#include "core/listeners.hpp"

GroupManager g_GroupManager;

// phmap::flat_hash_map<uint64_t, Group*> groups;

std::shared_mutex groups_mtx;

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
 * @param dontBroadcast
 * @return Success, ChildGroupNotFound, ParentGroupNotFound
 */
extern "C" PLUGIN_API Status SetParent(const int64_t pluginID, const plg::string& childName,
                                       const plg::string& parentName, const bool dontBroadcast)
{
    Group* g1 = g_GroupManager.Get(childName);
    Group* g2 = g_GroupManager.Get(parentName);

	const bool empty_group = childName.empty();

    if (!g1 && !empty_group)
    	return Status::ChildGroupNotFound;
    if (!g2)
        return Status::ParentGroupNotFound;

	if (set_parent_storage_callbacks(pluginID, childName, parentName))
		return Status::DBNotReady;

    g1->_parent.store(empty_group ? nullptr : g2);

	if (!dontBroadcast) {
		set_parent_callbacks(pluginID, childName, parentName);
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
    const Group* child = g_GroupManager.Get(groupName);

    if (!child)
        return Status::ChildGroupNotFound;
	const Group* parent = child->_parent.load();
    if (!parent)
        return Status::ParentGroupNotFound;
    parentName = parent->_name;
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
	Group* g = g_GroupManager.Get(name);

    perms = g->dumpPerms();

    return Status::Success;
}

/**
 * @brief Get all created groups
 *
 * @return Array of groups
 */
extern "C" PLUGIN_API plg::vector<plg::string> GetAllGroups()
{
    return g_GroupManager.DumpAllGroups();
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
	Group* g = g_GroupManager.Get(name);
	if (!g)
		return Status::GroupNotFound;

	if (perm.empty())
		return Status::Allow;

    bool w_wildcard;
    Status status = g->hasPermission(perm, exact, w_wildcard);
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
	Group* g1 = g_GroupManager.Get(childName);
	Group* g2 = g_GroupManager.Get(parentName);
    if (!g1)
        return Status::ChildGroupNotFound;
    if (!g2)
        return Status::ParentGroupNotFound;

    if (g1->hasParent(g2))
    	return Status::Allow;
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
	Group* g = g_GroupManager.Get(groupName);
	if (!g)
		return Status::GroupNotFound;
    priority = g->_priority;
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
                                                const plg::string& perm, const bool dontBroadcast) {
	if (perm.empty())
		return Status::Allow;
	Group* g = g_GroupManager.Get(name);
	if (!g)
		return Status::GroupNotFound;

	const bool denied = perm.starts_with('-');
	bool w_wildcard;
	const Status oldState = g->hasPermission(perm, true, w_wildcard);
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
		if (replaceToWC)
			act = Action::ReplaceToWC;
	}

	if (group_permission_storage_callbacks(pluginID, act, name, perm, oldState, denied ? Status::Disallow : Status::Allow))
		return Status::DBNotReady;

	g->addPerm(perm);

	if (!dontBroadcast) {
		group_permission_callbacks(pluginID, act, name, perm, oldState, denied ? Status::Disallow : Status::Allow);
	}

    return Status::Success;
}

extern "C" PLUGIN_API Status SetPermissionGroup(const int64_t pluginID, const plg::string& name,
												const plg::string& perm, const bool dontBroadcast)
{
	if (perm.empty())
		return Status::Allow;
	Group* g = g_GroupManager.Get(name);
	if (!g)
		return Status::GroupNotFound;

	const bool denied = perm.starts_with('-');
	bool w_wildcard;
	const Status oldState = g->hasPermission(perm, true, w_wildcard);
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
		if (replaceToWC)
			act = Action::ReplaceToWC;
	}

	if (!diff)
		return Status::PermAlreadyGranted;

	if (group_permission_storage_callbacks(pluginID, act, name, perm, oldState, denied ? Status::Disallow : Status::Allow))
		return Status::DBNotReady;

	g->addPerm(perm);

	if (!dontBroadcast) {
		group_permission_callbacks(pluginID, act, name, perm, oldState, denied ? Status::Disallow : Status::Allow);
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
                                                   const plg::string& perm, const bool recursiveDeletion, const bool dontBroadcast) {
	if (perm.empty())
		return Status::Success;
	Group* g = g_GroupManager.Get(name);
	if (!g)
		return Status::GroupNotFound;

	bool w_wildcard;
	const auto oldState = g->hasPermission(perm, true, w_wildcard);
	if (oldState == Status::PermNotFound)
		return Status::PermNotFound;

	if (group_permission_storage_callbacks(pluginID, Action::Remove, name, perm, oldState, Status::PermNotFound))
		return Status::DBNotReady;

	plg::vector<plg::string> deleted_perms;
	g->delPerm(perm, recursiveDeletion, deleted_perms);
	if (deleted_perms.size() == 0)
		deleted_perms.push_back(perm);

	if (!dontBroadcast) {
		for (const plg::string& s : deleted_perms)
			group_permission_callbacks(pluginID, Action::Remove, s, perm, oldState, Status::PermNotFound);
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
	Group* g = g_GroupManager.Get(groupName);
	if (!g)
		return Status::GroupNotFound;

    return g->getCookie(optionName, value) ? Status::Success : Status::OptionNotFound;
}

/**
 * @brief Set an option value for a group.
 *
 * @param pluginID Identifier of the plugin that calls the method.
 * @param groupName Group name
 * @param optionName Option name
 * @param value Option value.
 * @param dontBroadcast
 * @return Success, GroupNotFound
 */
extern "C" PLUGIN_API Status SetOptionGroup(const int64_t pluginID, const plg::string& groupName,
                                            const plg::string& optionName, const plg::any& value, const bool dontBroadcast)
{
	Group* g = g_GroupManager.Get(groupName);
	if (!g)
		return Status::GroupNotFound;

	if (group_option_storage_callbacks(pluginID, groupName, optionName, value))
		return Status::DBNotReady;

	g->setCookie(optionName, value);

	if (!dontBroadcast) {
		group_option_callbacks(pluginID, groupName, optionName, value);
	}

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
	Group* g = g_GroupManager.Get(groupName);
	if (!g)
		return Status::GroupNotFound;
	g->dumpCookies(optionNames, values);

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
 * @param dontBroadcast
 * @return Success, GroupAlreadyExist, ParentGroupNotFound
 */
extern "C" PLUGIN_API Status CreateGroup(const int64_t pluginID, const plg::string& name,
                                         const plg::vector<plg::string>& perms, const int priority,
                                         const plg::string& parent, const bool dontBroadcast)
{
	std::scoped_lock lock(global_mutex);
	if (g_GroupManager.Exists(name))
		return Status::GroupAlreadyExist;
	Group* parentGroup = nullptr;
	if (!parent.empty()) {
		parentGroup = g_GroupManager.Get(parent);
		if (!parentGroup)
			return Status::ParentGroupNotFound;
	}

	if (group_create_storage_callbacks(pluginID, name, perms, priority, parent))
		return Status::DBNotReady;

	g_GroupManager.Add(perms, name, priority, parentGroup);

	if (!dontBroadcast) {
		group_create_callbacks(pluginID, name, perms, priority, parent);
	}

    return Status::Success;
}

/**
 * @brief Delete a group.
 *
 * @param pluginID Identifier of the plugin that calls the method.
 * @param name Group name.
 * @param dontBroadcast
 * @return Success if deleted; GroupNotFound if group not found.
 */
extern "C" PLUGIN_API Status DeleteGroup(const int64_t pluginID, const plg::string& name, const bool dontBroadcast)
{
	std::scoped_lock lock(global_mutex);
	const Group* g = g_GroupManager.Get(name);
	if (!g)
		return Status::GroupNotFound;

	if (group_delete_storage_callbacks(pluginID, name))
		return Status::DBNotReady;

    g_GroupManager.Delete(name);

	plg::vector<uint64_t> users = g_UserManager.DumpAllUsers();
	time_t old_timestamp;
	for (const uint64_t user : users) {
		const std::shared_ptr<User> s_user = g_UserManager.Get(user);
		s_user->delGroup(g, old_timestamp);
	}

	if (!dontBroadcast) {
		group_delete_callbacks(pluginID, name);
	}

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
    return g_GroupManager.Exists(name);
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
 * @param pluginID   Identifier of the calling plugin.
 * @param dontBroadcast
 */
extern "C" PLUGIN_API Status LoadGroups(const int64_t pluginID, [[maybe_unused]] const bool dontBroadcast)
{
	if (load_groups_callbacks(pluginID))
		return Status::DBNotReady;

	return Status::Success;
}

PLUGIFY_WARN_POP()
