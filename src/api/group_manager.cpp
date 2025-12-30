#include "group_manager.h"
phmap::flat_hash_map<uint64_t, Group*> groups;

std::shared_mutex groups_mtx;

PLUGIFY_WARN_PUSH()

#if defined(__clang__)
PLUGIFY_WARN_IGNORE ("-Wreturn-type-c-linkage")
#elif defined(_MSC_VER)
PLUGIFY_WARN_IGNORE(4190)
#endif

/**
 * @brief Set parent group for child group
 *
 * @param child_name Child group name
 * @param parent_name Parent group name to set
 * @return SUCCESS | GROUP1_NOT_FOUND | GROUP2_NOT_FOUND
 */
extern "C" PLUGIN_API Status SetParent(const plg::string& child_name, const plg::string& parent_name) {
	const uint64_t hash1 = XXH3_64bits(child_name.data(), child_name.size());
	const uint64_t hash2 = XXH3_64bits(parent_name.data(), parent_name.size());
	std::unique_lock lock(groups_mtx);
	const auto it1 = groups.find(hash1);
	const auto it2 = groups.find(hash2);

	if (it1 == groups.end())
		return Status::GROUP1_NOT_FOUND;
	if (it2 == groups.end())
		return Status::GROUP2_NOT_FOUND;

	it1->second->_parent = it2->second;
	return Status::SUCCESS;
}

/**
 * @brief Get parent of requested group
 *
 * @param name Group name
 * @param output Parent name
 * @return SUCCESS | GROUP1_NOT_FOUND | GROUP2_NOT_FOUND
 */
extern "C" PLUGIN_API Status GetParent(const plg::string& name, plg::string& output) {
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::shared_lock lock(groups_mtx);
	const auto it = groups.find(hash);

	if (it == groups.end())
		return Status::GROUP1_NOT_FOUND;
	if (!it->second->_parent)
		return Status::GROUP2_NOT_FOUND;
	output = it->second->_parent->_name;
	return Status::SUCCESS;
}

/**
 * @brief Get permissions of group
 *
 * @param name Group name
 * @param perms Permissions
 * @return SUCCESS | GROUP1_NOT_FOUND
 */
extern "C" PLUGIN_API Status DumpPermissionsGroup(const plg::string& name, plg::vector<plg::string>& perms) {
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::shared_lock lock(groups_mtx);
	const auto v = groups.find(hash);
	if (v == groups.end()) Status::GROUP1_NOT_FOUND;

	perms = dumpNode(v->second->_nodes);

	return Status::SUCCESS;
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
 * @return ALLOW | DISALLOW | PERM_NOT_FOUND | GROUP1_NOT_FOUND
 */
extern "C" PLUGIN_API Status HasPermissionGroup(const plg::string& name, const plg::string& perm) {
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::shared_lock lock(groups_mtx);
	const auto it = groups.find(hash);
	if (it == groups.end()) return Status::GROUP1_NOT_FOUND;
	return it->second->hasPermission(perm);
}

/**
 * @brief Check if parent_name is a parent group for child_name.
 *
 * @param child_name Child group name.
 * @param parent_name Parent group name to check.
 * @return ALLOW | DISALLOW | GROUP1_NOT_FOUND | GROUP2_NOT_FOUND
 */
extern "C" PLUGIN_API Status HasParentGroup(const plg::string& child_name, const plg::string& parent_name) {
	const uint64_t hash1 = XXH3_64bits(child_name.data(), child_name.size());
	const uint64_t hash2 = XXH3_64bits(parent_name.data(), parent_name.size());
	std::shared_lock lock(groups_mtx);
	const auto it1 = groups.find(hash1);
	const auto it2 = groups.find(hash2);
	if (it1 == groups.end())
		return Status::GROUP1_NOT_FOUND;
	if (it2 == groups.end())
		return Status::GROUP2_NOT_FOUND;

	const Group* g1 = it1->second;
	const Group* g2 = it2->second;
	while (g1) {
		if (g1->_parent == g2) return Status::ALLOW;
		g1 = g1->_parent;
	}
	return Status::DISALLOW;
}

/**
 * @brief Get the priority of a group.
 *
 * @param name Group name.
 * @param priority Priority
 * @return SUCCESS | GROUP1_NOT_FOUND
 */
extern "C" PLUGIN_API Status GetPriorityGroup(const plg::string& name, int& priority) {
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::shared_lock lock(groups_mtx);
	const auto it = groups.find(hash);
	if (it == groups.end()) Status::GROUP1_NOT_FOUND;
	priority = it->second->_priority;
	return Status::SUCCESS;
}

/**
 * @brief Add a permission to a group.
 *
 * @param name Group name.
 * @param perm Permission line.
 * @return SUCCESS | GROUP1_NOT_FOUND
 */
extern "C" PLUGIN_API Status AddPermissionGroup(const plg::string& name, const plg::string& perm) {
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::unique_lock lock1(groups_mtx);
	const auto it = groups.find(hash);
	if (it == groups.end()) Status::GROUP1_NOT_FOUND;

	std::unique_lock lock2(users_mtx);
	it->second->_nodes.addPerm(perm);
	return Status::SUCCESS;
}

/**
 * @brief Remove a permission from a group.
 *
 * @param name Group name.
 * @param perm Permission line.
 * @return SUCCESS | GROUP1_NOT_FOUND
 */
extern "C" PLUGIN_API Status RemovePermissionGroup(const plg::string& name, const plg::string& perm) {
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::unique_lock lock1(groups_mtx);
	const auto it = groups.find(hash);
	if (it == groups.end()) return Status::GROUP1_NOT_FOUND;

	std::unique_lock lock2(users_mtx);
	it->second->_nodes.deletePerm(perm);
	return Status::SUCCESS;
}

/**
 * @brief Get a cookie value for a group.
 *
 * @param gname Group name
 * @param cname Cookie name
 * @param cookie Cookie value
 * @return SUCCESS | COOKIE_NOT_FOUND | GROUP1_NOT_FOUND
 */
extern "C" PLUGIN_API Status GetCookieGroup(const plg::string& gname, const plg::string& cname, plg::any& cookie) {
	const uint64_t hash = XXH3_64bits(gname.data(), gname.size());
	std::shared_lock lock(groups_mtx);
	const auto v = groups.find(hash);
	if (v == groups.end()) return Status::GROUP1_NOT_FOUND;

	Group* g = v->second;
	while (g != nullptr) {
		const auto val = g->cookies.find(cname);
		if (val == g->cookies.end()) {
			g = g->_parent;
			continue;
		}
		cookie = val->second;
		return Status::SUCCESS;
	}
	return Status::COOKIE_NOT_FOUND;
}

/**
 * @brief Set a cookie value for a group.
 *
 * @param gname Group name
 * @param cname Cookie name
 * @param cookie Cookie value.
 * @return SUCCESS | GROUP1_NOT_FOUND
 */
extern "C" PLUGIN_API Status SetCookieGroup(const plg::string& gname, const plg::string& cname, const plg::any& cookie) {
	const uint64_t hash = XXH3_64bits(gname.data(), gname.size());
	std::unique_lock lock(groups_mtx);
	const auto v = groups.find(hash);
	if (v == groups.end()) return Status::GROUP1_NOT_FOUND;

	std::unique_lock lock2(users_mtx);
	v->second->cookies[cname] = cookie;
	return Status::SUCCESS;
}

/**
 * @brief Get all cookies from group.
 *
 * @param gname Group name
 * @param names Array of cookie names
 * @param values Array of cookie values
 * @return SUCCESS | GROUP1_NOT_FOUND
 */

extern "C" PLUGIN_API Status GetAllCookiesGroup(const plg::string& gname, plg::vector<plg::string>& names, plg::vector<plg::any>& values) {
	const uint64_t hash = XXH3_64bits(gname.data(), gname.size());
	std::shared_lock lock(groups_mtx);
	const auto v = groups.find(hash);
	if (v == groups.end()) return Status::GROUP1_NOT_FOUND;

	names.clear();
	values.clear();

	for (const auto& [kv, vv]: v->second->cookies) {
		names.push_back(kv);
		values.push_back(vv);
	}

	return Status::SUCCESS;
}

/**
 * @brief Create a new group.
 *
 * @param name Group name.
 * @param perms Array of permission lines.
 * @param priority Group priority.
 * @param parent Parent group name.
 * @return SUCCESS | GROUP_ALREADY_EXIST | GROUP1_NOT_FOUND
 */
extern "C" PLUGIN_API Status CreateGroup(const plg::string& name, const plg::vector<plg::string>& perms, const int priority, const plg::string& parent) {
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::unique_lock lock(groups_mtx);
	if (groups.contains(hash)) return Status::GROUP_ALREADY_EXIST;
	Group* gparent = nullptr;
	if (!parent.empty()) {
		gparent = GetGroup(parent);
		if (!gparent) return Status::GROUP1_NOT_FOUND;
	}

	auto* group = new Group(perms, name, priority, gparent);
	groups.try_emplace(hash, group);
	return Status::SUCCESS;
}

/**
 * @brief Delete a group.
 *
 * @param name Group name.
 * @return True if deleted; false if group not found.
 */
extern "C" PLUGIN_API Status DeleteGroup(const plg::string& name) {
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::unique_lock lock(groups_mtx);
	const auto it = groups.find(hash);
	if (it == groups.end()) return Status::GROUP1_NOT_FOUND;

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

	GroupManager_Callback(gg); // Delete group in users
	delete gg;
	return Status::SUCCESS;
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

PLUGIFY_WARN_POP()