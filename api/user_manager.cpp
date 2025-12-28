#include "user_manager.h"
phmap::flat_hash_map<uint64_t, User> users;

std::shared_mutex users_mtx;

PLUGIFY_WARN_PUSH()

#if defined(__clang__)
PLUGIFY_WARN_IGNORE ("-Wreturn-type-c-linkage")
#elif defined(_MSC_VER)
PLUGIFY_WARN_IGNORE(4190)
#endif

/**
 * @brief Get permissions of user
 *
 * @param id Player ID
 * @param perms Permissions
 * @return SUCCESS | USER1_NOT_FOUND
 */
extern "C" PLUGIN_API Status DumpPermissions(const uint64_t id, plg::vector<plg::string>& perms) {
	std::shared_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end()) return Status::USER1_NOT_FOUND;

	perms = dumpNode(v->second.nodes);

	return Status::SUCCESS;
}

/**
 * @brief Check players immunity or groups priority
 *
 * @param id1 Player ID
 * @param id2 Player ID
 * @return ALLOW | DISALLOW | USER1_NOT_FOUND | USER2_NOT_FOUND
 */
extern "C" PLUGIN_API Status CanAffectUser(const uint64_t id1, const uint64_t id2) {
	std::shared_lock lock(users_mtx);
	const auto v1 = users.find(id1);
	const auto v2 = users.find(id2);
	if (v1 == users.end())
		return Status::USER1_NOT_FOUND;
	if (v2 == users.end())
		return Status::USER2_NOT_FOUND;

	const auto i1 = v1->second._immunity == -1 ? (v1->second._groups.empty() ? -1 : v1->second._groups.front()->_priority) : v1->second._immunity;
	const auto i2 = v2->second._immunity == -1 ? (v2->second._groups.empty() ? -1 : v2->second._groups.front()->_priority) : v2->second._immunity;

	return i1 >= i2 ? Status::ALLOW : Status::DISALLOW;
}

/**
 * @brief Check if a user has a specific permission.
 *
 * @param id Player ID.
 * @param perm Permission line.
 * @return ALLOW | DISALLOW | PERM_NOT_FOUND | USER1_NOT_FOUND
 *
 */
extern "C" PLUGIN_API Status HasPermission(const uint64_t id, const plg::string& perm) {
	std::shared_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v != users.end()) return v->second.hasPermission(perm);
	return Status::USER1_NOT_FOUND;
}

/**
 * @brief Check if a user belongs to a specific group (directly or via parent groups).
 *
 * @param id Player ID.
 * @param group Group name.
 * @return ALLOW | DISALLOW | USER1_NOT_FOUND | GROUP1_NOT_FOUND
 */
extern "C" PLUGIN_API Status HasGroup(const uint64_t id, const plg::string& group) {
	std::shared_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end()) return Status::USER1_NOT_FOUND;

	const Group* g = GetGroup(group);
	if (g == nullptr)
		return Status::GROUP1_NOT_FOUND;

	for (const auto gg: v->second._groups) {
		auto ggg = gg;
		while (ggg) {
			if (ggg == g) return Status::ALLOW;
			ggg = ggg->_parent;
		}
	}
	return Status::DISALLOW;
}

/**
 * @Brief Get user groups.
 *
 * @param id Player ID.
 * @param ogroups Groups
 * @return SUCCESS | USER1_NOT_FOUND
 */
extern "C" PLUGIN_API Status GetUserGroups(const uint64_t id, plg::vector<plg::string>& ogroups) {
	std::shared_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end()) return Status::USER1_NOT_FOUND;

	ogroups.clear();
	ogroups.reserve(v->second._groups.size());
	for (const auto g: v->second._groups)
		ogroups.push_back(g->_name);

	return Status::SUCCESS;
}

/**
 * @brief Get the immunity level of a user.
 *
 * @param id Player ID.
 * @param immunity Immunity
 * @return SUCCESS | USER1_NOT_FOUND
 */
extern "C" PLUGIN_API Status GetImmunity(const uint64_t id, int& immunity) {
	std::shared_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end()) return Status::USER1_NOT_FOUND;
	immunity = v->second._immunity;
	return Status::SUCCESS;
}

/**
 * @brief Add a permission to a user.
 *
 * @param id Player ID.
 * @param perm Permission line.
 * @return SUCCESS | USER1_NOT_FOUND
 */
extern "C" PLUGIN_API Status AddPermission(const uint64_t id, const plg::string& perm) {
	std::unique_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end()) return Status::USER1_NOT_FOUND;
	v->second.nodes.addPerm(perm);
	return Status::SUCCESS;
}

/**
 * @brief Add a permissions to a user.
 *
 * @param id Player ID
 * @param perms Permissions array
 * @return SUCCESS | USER1_NOT_FOUND
 */
extern "C" PLUGIN_API Status AddPermissions(const uint64_t id, const plg::vector<plg::string>& perms) {
	std::unique_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end()) return Status::USER1_NOT_FOUND;

	for (const auto& perm: perms) v->second.nodes.addPerm(perm);
	return Status::SUCCESS;
}

/**
 * @brief Remove a permission from a user.
 *
 * @param id Player ID.
 * @param perm Permission line.
 * @return SUCCESS | USER1_NOT_FOUND
 */
extern "C" PLUGIN_API Status RemovePermission(const uint64_t id, const plg::string& perm) {
	std::unique_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end()) return Status::USER1_NOT_FOUND;

	v->second.nodes.deletePerm(perm);
	return Status::SUCCESS;
}

/**
 * @brief Remove a permissions to a user.
 *
 * @param id Player ID
 * @param perms Permissions array
 * @return SUCCESS | USER1_NOT_FOUND
 */
extern "C" PLUGIN_API Status RemovePermissions(const uint64_t id, const plg::vector<plg::string>& perms) {
	std::unique_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end()) return Status::USER1_NOT_FOUND;

	for (const auto& perm: perms) v->second.nodes.deletePerm(perm);
	return Status::SUCCESS;
}

/**
 * @brief Add a group to a user.
 *
 * @param id Player ID.
 * @param group Group name.
 * @return SUCCESS | USER1_NOT_FOUND | GROUP1_NOT_FOUND | GROUP_ALREADY_EXIST
 */
extern "C" PLUGIN_API Status AddGroup(const uint64_t id, const plg::string& group) {
	std::unique_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end()) return Status::USER1_NOT_FOUND;

	Group* g = GetGroup(group);
	if (g == nullptr)
		return Status::GROUP1_NOT_FOUND;
	for (const auto gg: v->second._groups) {
		const Group* ggg = gg;
		while (ggg) {
			if (ggg == g) return Status::GROUP_ALREADY_EXIST;
			ggg = ggg->_parent;
		}
	}
	v->second._groups.push_back(g);
	v->second.sortGroups();
	return Status::SUCCESS;
}

/**
 * @brief Remove a group from a user.
 *
 * @param id Player ID.
 * @param group Group name.
 * @return SUCCESS | USER1_NOT_FOUND | GROUP1_NOT_FOUND | GROUP2_NOT_FOUND
 */
extern "C" PLUGIN_API Status RemoveGroup(const uint64_t id, const plg::string& group) {
	std::unique_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end()) return Status::USER1_NOT_FOUND;

	Group* g = GetGroup(group);
	if (g == nullptr)
		return Status::GROUP1_NOT_FOUND;
	const auto it = v->second._groups.find(g);
	if (it == v->second._groups.end()) return Status::GROUP2_NOT_FOUND;
	v->second._groups.erase(it);
	return Status::SUCCESS;
}

/**
 * @brief Get a cookie value for a user.
 *
 * @param id Player ID.
 * @param name Cookie name.
 * @param cookie Cookie value.
 * @return SUCCESS | USER1_NOT_FOUND | COOKIE_NOT_FOUND
 */
extern "C" PLUGIN_API Status GetCookie(uint64_t id, const plg::string& name, plg::any& cookie) {
	std::shared_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end()) return Status::USER1_NOT_FOUND;

	auto val = v->second.cookies.find(name);
	bool found = val != v->second.cookies.end();
	if (!found) {
		// Check in groups cookies
		for (Group* g: v->second._groups) {
			Group* gg = g;
			while (gg) {
				val = gg->cookies.find(name);
				found = val != gg->cookies.end();
				if (found)
					break;
				gg = gg->_parent;
			}
		}
	}
	if (found)
		cookie = val->second;
	return found ? Status::SUCCESS : Status::COOKIE_NOT_FOUND;
}

/**
 * @brief Set a cookie value for a user.
 *
 * @param id Player ID.
 * @param name Cookie name.
 * @param cookie Cookie value.
 * @return SUCCESS | USER1_NOT_FOUND
 */
extern "C" PLUGIN_API Status SetCookie(uint64_t id, const plg::string& name, const plg::any& cookie) {
	std::unique_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end()) return Status::USER1_NOT_FOUND;

	v->second.cookies[name] = cookie;
	return Status::SUCCESS;
}

/**
 * @brief Get all cookies from user.
 *
 * @param id Player ID.
 * @param names Array of cookie names
 * @param values Array of cookie values
 * @return SUCCESS | USER1_NOT_FOUND
 */

extern "C" PLUGIN_API Status GetAllCookies(const uint64_t id, plg::vector<plg::string>& names, plg::vector<plg::any>& values) {
	std::shared_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end()) return Status::USER1_NOT_FOUND;

	names.clear();
	values.clear();

	for (const auto& [kv, vv]: v->second.cookies) {
		names.push_back(kv);
		values.push_back(vv);
	}

	return Status::SUCCESS;
}

/**
 * @brief Create a new user.
 *
 * @param id Player ID.
 * @param immunity User immunity (set -1 to return highest group priotiry).
 * @param lgroups Array of groups to inherit.
 * @param perms Array of permissions.
 * @return SUCCESS | USER_ALREADY_EXIST | GROUP1_NOT_FOUND
 */
extern "C" PLUGIN_API Status CreateUser(uint64_t id, int immunity, const plg::vector<plg::string>& lgroups, const plg::vector<plg::string>& perms) {
	std::unique_lock lock(users_mtx);
	if (users.contains(id)) return Status::USER_ALREADY_EXIST;

	plg::vector<Group*> llgroups;
	llgroups.reserve(lgroups.size());
	for (auto& lgroup: lgroups) {
		Group* gg = GetGroup(lgroup);
		if (gg == nullptr) return Status::GROUP1_NOT_FOUND;
		llgroups.push_back(gg);
	}

	users.try_emplace(id, immunity, std::move(llgroups), perms);
	return Status::SUCCESS;
}

/**
 * @brief Delete a user.
 *
 * @param id Player ID.
 * @return SUCCESS | USER1_NOT_FOUND
 */
extern "C" PLUGIN_API Status DeleteUser(const uint64_t id) {
	std::unique_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end()) return Status::USER1_NOT_FOUND;

	users.erase(v);
	return true;
}

/**
 * @brief Check if a user exists.
 *
 * @param id Player ID.
 * @return True if user exists, false otherwise.
 */
extern "C" PLUGIN_API bool UserExists(const uint64_t id) {
	std::shared_lock lock(users_mtx);
	const auto v = users.find(id);
	return v != users.end();
}

PLUGIFY_WARN_POP()