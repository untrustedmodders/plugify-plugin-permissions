#include "groupManager.h"

/**
 * @brief Set parent group for child group
 *
 * @param child_name Child group name
 * @param parent_name Parent group name to set
 * @return True if both groups exist, otherwise false
 */
extern "C" PLUGIN_API bool SetParent(const plg::string& child_name, const plg::string& parent_name) {
	const uint64_t hash1 = XXH3_64bits(child_name.data(), child_name.size());
	const uint64_t hash2 = XXH3_64bits(parent_name.data(), parent_name.size());
	std::unique_lock lock(groups_mtx);
	const auto it1 = groups.find(hash1);
	const auto it2 = groups.find(hash2);

	if (it1 == groups.end() || it2 == groups.end()) return false;

	it1->second->_parent = it2->second;
	return true;
}

/**
 * @brief Get permissions of group
 *
 * @param name Group name
 * @return Array of group permissions
 */
extern "C" PLUGIN_API plg::vector<plg::string> DumpPermissionsGroup(const plg::string& name) {
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::shared_lock lock(groups_mtx);
	const auto v = groups.find(hash);
	if (v == groups.end()) return {};

	plg::vector<plg::string> perms = dumpNode(v->second->_nodes);

	return perms;
}

/**
 * @brief Check if a group has a specific permission.
 *
 * @param name Group name.
 * @param perm Permission line.
 * @return Return value indicating access status.
 */
extern "C" PLUGIN_API Access HasPermissionGroup(const plg::string& name, const plg::string& perm) {
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::shared_lock lock(groups_mtx);
	const auto it = groups.find(hash);
	if (it == groups.end()) return Access::NotFound;
	return it->second->hasPermission(perm);
}

/**
 * @brief Check if parent_name is a parent group for child_name.
 *
 * @param child_name Child group name.
 * @param parent_name Parent group name to check.
 * @return True if name2 is among parents of child_name, otherwise false.
 */
extern "C" PLUGIN_API bool HasParentGroup(const plg::string& child_name, const plg::string& parent_name) {
	const uint64_t hash1 = XXH3_64bits(child_name.data(), child_name.size());
	const uint64_t hash2 = XXH3_64bits(parent_name.data(), parent_name.size());
	std::shared_lock lock(groups_mtx);
	const auto it1 = groups.find(hash1);
	const auto it2 = groups.find(hash2);
	if (it1 == groups.end() || it2 == groups.end()) return false;

	const Group* g1 = it1->second;
	const Group* g2 = it2->second;
	while (g1) {
		if (g1->_parent == g2) return true;
		g1 = g1->_parent;
	}
	return false;
}

/**
 * @brief Get the priority of a group.
 *
 * @param name Group name.
 * @return Group priority, or 0 if not found.
 */
extern "C" PLUGIN_API int GetPriorityGroup(const plg::string& name) {
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::shared_lock lock(groups_mtx);
	const auto it = groups.find(hash);
	if (it == groups.end()) return 0;
	return it->second->_priority;
}

/**
 * @brief Add a permission to a group.
 *
 * @param name Group name.
 * @param perm Permission line.
 * @return True if successful; false if group not found.
 */
extern "C" PLUGIN_API bool AddPermissionGroup(const plg::string& name, const plg::string& perm) {
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::unique_lock lock1(groups_mtx);
	const auto it = groups.find(hash);
	if (it == groups.end()) return false;
	std::unique_lock lock2(users_mtx);
	it->second->_nodes.addPerm(perm);
	return true;
}

/**
 * @brief Remove a permission from a group.
 *
 * @param name Group name.
 * @param perm Permission line.
 * @return True if successful; false if group not found.
 */
extern "C" PLUGIN_API bool RemovePermissionGroup(const plg::string& name, const plg::string& perm) {
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::unique_lock lock1(groups_mtx);
	const auto it = groups.find(hash);
	if (it == groups.end()) return false;
	std::unique_lock lock2(users_mtx);
	it->second->_nodes.deletePerm(perm);
	return true;
}

/**
 * @brief Create a new group.
 *
 * @param name Group name.
 * @param perms Array of permission lines.
 * @param priority Group priority.
 * @param parent Parent group pointer.
 * @return True if created; false if group already exists.
 */
extern "C" PLUGIN_API bool CreateGroup(const plg::string& name, const plg::vector<plg::string>& perms, const int priority, Group* parent) {
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::unique_lock lock(groups_mtx);
	if (groups.contains(hash)) return false;

	auto* group = new Group(perms, name, priority, parent);
	groups.try_emplace(hash, group);
	return true;
}

/**
 * @brief Delete a group.
 *
 * @param name Group name.
 * @return True if deleted; false if group not found.
 */
extern "C" PLUGIN_API bool DeleteGroup(const plg::string& name) {
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::unique_lock lock(groups_mtx);
	const auto it = groups.find(hash);
	if (it == groups.end()) return false;

	const Group* gg = it->second;
	groups.erase(it);

	// Cleanup parent references in other groups
	for (const auto value: groups | std::views::values) {
		Group* g = value;
		while (g) {
			if (g->_parent == gg) {
				g->_parent = nullptr;
				break;
			}
			g = g->_parent;
		}
	}

	GroupManager_Callback(gg);
	delete gg;
	return true;
}