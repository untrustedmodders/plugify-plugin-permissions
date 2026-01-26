#include "group_manager.h"
phmap::flat_hash_map<uint64_t, Group*> groups;

std::shared_mutex groups_mtx;

SetParentCallbacks set_parent_callbacks;
SetCookieGroupCallbacks set_cookie_group_callbacks;
GroupPermissionCallbacks group_permission_callbacks;
GroupCreateCallbacks group_create_callbacks;
GroupDeleteCallbacks group_delete_callbacks;

PLUGIFY_WARN_PUSH()

#if defined(__clang__)
PLUGIFY_WARN_IGNORE("-Wreturn-type-c-linkage")
#elif defined(_MSC_VER)
PLUGIFY_WARN_IGNORE(4190)
#endif

/**
 * @brief Set parent group for child group
 *
 * @param childName Child group name
 * @param parentName Parent group name to set
 * @return Success, ChildGroupNotFound, ParentGroupNotFound
 */
extern "C" PLUGIN_API Status SetParent(const plg::string& childName, const plg::string& parentName) {
	const uint64_t hash1 = XXH3_64bits(childName.data(), childName.size());
	const uint64_t hash2 = XXH3_64bits(parentName.data(), parentName.size());
	std::unique_lock lock(groups_mtx);
	const auto it1 = groups.find(hash1);
	const auto it2 = groups.find(hash2);

	if (it1 == groups.end())
		return Status::ChildGroupNotFound;
	if (it2 == groups.end())
		return Status::ParentGroupNotFound;

	it1->second->_parent = it2->second;
	{
		std::shared_lock lock2(set_parent_callbacks._lock);
		for (const SetParentCallback cb : set_parent_callbacks._callbacks)
			cb(childName, parentName);
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
extern "C" PLUGIN_API Status GetParent(const plg::string& groupName, plg::string& parentName) {
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
extern "C" PLUGIN_API Status DumpPermissionsGroup(const plg::string& name, plg::vector<plg::string>& perms) {
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::shared_lock lock(groups_mtx);
	const auto v = groups.find(hash);
	if (v == groups.end())
		return Status::ChildGroupNotFound;

	perms = dumpNode(v->second->_nodes);

	return Status::Success;
}

/**
 * @brief Get all created groups
 *
 * @return Array of groups
 */
extern "C" PLUGIN_API plg::vector<plg::string> GetAllGroups() {
	std::shared_lock lock(groups_mtx);

	plg::vector<plg::string> lgroups;
	lgroups.reserve(groups.size());
	for (const auto& [kv, vv]: groups)
		lgroups.push_back(vv->_name);

	return lgroups;
}

/**
 * @brief Check if a group has a specific permission.
 *
 * @param name Group name.
 * @param perm Permission line.
 * @return Allow, Disallow, PermNotFound, GroupNotFound
 */
extern "C" PLUGIN_API Status HasPermissionGroup(const plg::string& name, const plg::string& perm) {
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::shared_lock lock(groups_mtx);
	const auto it = groups.find(hash);
	if (it == groups.end())
		return Status::GroupNotFound;
	return it->second->hasPermission(perm);
}

/**
 * @brief Check if parent_name is a parent group for child_name.
 *
 * @param childName Child group name.
 * @param parentName Parent group name to check.
 * @return Allow, Disallow, ChildGroupNotFound, ParentGroupNotFound
 */
extern "C" PLUGIN_API Status HasParentGroup(const plg::string& childName, const plg::string& parentName) {
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
	while (g1) {
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
extern "C" PLUGIN_API Status GetPriorityGroup(const plg::string& groupName, int& priority) {
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
 * @param name Group name.
 * @param perm Permission line.
 * @return Success, GroupNotFound
 */
extern "C" PLUGIN_API Status AddPermissionGroup(const plg::string& name, const plg::string& perm) {
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::unique_lock lock1(groups_mtx);
	const auto it = groups.find(hash);
	if (it == groups.end())
		return Status::GroupNotFound;

	std::unique_lock lock2(users_mtx); // Need to eliminate race in user-group permissions check
	it->second->_nodes.addPerm(perm);
	{
		std::shared_lock lock3(group_permission_callbacks._lock);
		for (const GroupPermissionCallback cb : group_permission_callbacks._callbacks)
			cb(Action::Remove, name, perm);
	}
	return Status::Success;
}

/**
 * @brief Remove a permission from a group.
 *
 * @param name Group name.
 * @param perm Permission line.
 * @return Success, GroupNotFound
 */
extern "C" PLUGIN_API Status RemovePermissionGroup(const plg::string& name, const plg::string& perm) {
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::unique_lock lock1(groups_mtx);
	const auto it = groups.find(hash);
	if (it == groups.end())
		return Status::GroupNotFound;

	std::unique_lock lock2(users_mtx);
	{
		std::shared_lock lock3(group_permission_callbacks._lock);
		for (const GroupPermissionCallback cb : group_permission_callbacks._callbacks)
			cb(Action::Remove, name, perm);
	}
	it->second->_nodes.deletePerm(perm);
	return Status::Success;
}

/**
 * @brief Get a cookie value for a group.
 *
 * @param groupName Group name
 * @param cookieName Cookie name
 * @param value Cookie value
 * @return Success, CookieNotFound, GroupNotFound
 */
extern "C" PLUGIN_API Status GetCookieGroup(const plg::string& groupName, const plg::string& cookieName, plg::any& value) {
	const uint64_t hash = XXH3_64bits(groupName.data(), groupName.size());
	std::shared_lock lock(groups_mtx);
	const auto v = groups.find(hash);
	if (v == groups.end())
		return Status::GroupNotFound;

	Group* g = v->second;
	while (g != nullptr) {
		const auto val = g->cookies.find(cookieName);
		if (val == g->cookies.end()) {
			g = g->_parent;
			continue;
		}
		value = val->second;
		return Status::Success;
	}
	return Status::CookieNotFound;
}

/**
 * @brief Set a cookie value for a group.
 *
 * @param groupName Group name
 * @param cookieName Cookie name
 * @param value Cookie value.
 * @return Success, GroupNotFound
 */
extern "C" PLUGIN_API Status SetCookieGroup(const plg::string& groupName, const plg::string& cookieName, const plg::any& value) {
	const uint64_t hash = XXH3_64bits(groupName.data(), groupName.size());
	std::unique_lock lock(groups_mtx);
	const auto v = groups.find(hash);
	if (v == groups.end())
		return Status::GroupNotFound;

	std::unique_lock lock2(users_mtx);
	{
		std::shared_lock lock3(set_cookie_group_callbacks._lock);
		for (const SetCookieGroupCallback cb : set_cookie_group_callbacks._callbacks)
			cb(groupName, cookieName, value);
	}
	v->second->cookies[cookieName] = value;
	return Status::Success;
}

/**
 * @brief Get all cookies from group.
 *
 * @param groupName Group name
 * @param cookieNames Array of cookie names
 * @param values Array of cookie values
 * @return Success, GroupNotFound
 */

extern "C" PLUGIN_API Status GetAllCookiesGroup(const plg::string& groupName, plg::vector<plg::string>& cookieNames, plg::vector<plg::any>& values) {
	const uint64_t hash = XXH3_64bits(groupName.data(), groupName.size());
	std::shared_lock lock(groups_mtx);
	const auto v = groups.find(hash);
	if (v == groups.end())
		return Status::GroupNotFound;

	cookieNames.clear();
	values.clear();

	for (const auto& [kv, vv]: v->second->cookies) {
		cookieNames.push_back(kv);
		values.push_back(vv);
	}

	return Status::Success;
}

/**
 * @brief Create a new group.
 *
 * @param name Group name.
 * @param perms Array of permission lines.
 * @param priority Group priority.
 * @param parent Parent group name.
 * @return Success, GroupAlreadyExist, ParentGroupNotFound
 */
extern "C" PLUGIN_API Status CreateGroup(const plg::string& name, const plg::vector<plg::string>& perms, const int priority, const plg::string& parent) {
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::unique_lock lock(groups_mtx);
	if (groups.contains(hash))
		return Status::GroupAlreadyExist;
	Group* parentGroup = nullptr;
	if (!parent.empty()) {
		parentGroup = GetGroup(parent);
		if (!parentGroup) return Status::ParentGroupNotFound;
	}

	auto* group = new Group(perms, name, priority, parentGroup);
	groups.try_emplace(hash, group);
	{
		std::shared_lock lock2(group_create_callbacks._lock);
		for (GroupCreateCallback cb : group_create_callbacks._callbacks)
			cb(name, perms, priority, parent);
	}
	return Status::Success;
}

/**
 * @brief Delete a group.
 *
 * @param name Group name.
 * @return Success if deleted; GroupNotFound if group not found.
 */
extern "C" PLUGIN_API Status DeleteGroup(const plg::string& name) {
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::unique_lock lock(groups_mtx);
	const auto it = groups.find(hash);
	if (it == groups.end())
		return Status::GroupNotFound;

	{
		std::shared_lock lock2(group_delete_callbacks._lock);
		for (GroupDeleteCallback cb : group_delete_callbacks._callbacks)
			cb(name);
	}
	const Group* gg = it->second;
	groups.erase(it);

	// Cleanup parent references in other groups
	for (Group* value: groups | std::views::values) {
		Group* g = value;
		while (g) {
			if (g->_parent == gg) {
				g->_parent = nullptr;
				break;
			}
			g = g->_parent;
		}
	}

	GroupManager_Callback(gg);// Delete group in users
	delete gg;
	return Status::Success;
}

/**
 * @brief Check if a group exists.
 *
 * @param name Group name.
 * @return True if group exists, false otherwise.
 */
extern "C" PLUGIN_API bool GroupExists(const plg::string& name) {
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::unique_lock lock(groups_mtx);
	const auto v = groups.find(hash);
	return v != groups.end();
}

/**
 * @brief Register listener on group parent changing
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnGroupSetParent_Register(SetParentCallback callback) {
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
extern "C" PLUGIN_API Status OnGroupSetParent_Unregister(SetParentCallback callback) {
	std::unique_lock lock(set_parent_callbacks._lock);
	const size_t ret = set_parent_callbacks._callbacks.erase(callback);
	return ret > 0 ? Status::Success : Status::CallbackNotFound;
}

/**
 * @brief Register listener on group cookie sets
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnGroupSetCookie_Register(SetCookieGroupCallback callback) {
	std::unique_lock lock(set_cookie_group_callbacks._lock);
	auto ret = set_cookie_group_callbacks._callbacks.insert(callback);
	return ret.second ? Status::Success : Status::CallbackAlreadyExist;
}

/**
 * @brief Unregister listener on group cookie sets
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnGroupSetCookie_Unregister(SetCookieGroupCallback callback) {
	std::unique_lock lock(set_cookie_group_callbacks._lock);
	const size_t ret = set_cookie_group_callbacks._callbacks.erase(callback);
	return ret > 0 ? Status::Success : Status::CallbackNotFound;
}

/**
 * @brief Register listener on group permissions add/remove
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnGroupPermissionChange_Register(GroupPermissionCallback callback) {
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
extern "C" PLUGIN_API Status OnGroupPermissionChange_Unregister(GroupPermissionCallback callback) {
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
extern "C" PLUGIN_API Status OnGroupCreate_Register(GroupCreateCallback callback) {
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
extern "C" PLUGIN_API Status OnGroupCreate_Unregister(GroupCreateCallback callback) {
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
extern "C" PLUGIN_API Status OnGroupDelete_Register(GroupDeleteCallback callback) {
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
extern "C" PLUGIN_API Status OnGroupDelete_Unregister(GroupDeleteCallback callback) {
	std::unique_lock lock(group_delete_callbacks._lock);
	const size_t ret = group_delete_callbacks._callbacks.erase(callback);
	return ret > 0 ? Status::Success : Status::CallbackNotFound;
}

PLUGIFY_WARN_POP()