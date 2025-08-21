#include "userManager.h"

/**
 * @brief Check if a user has a specific permission.
 *
 * @param id Player ID.
 * @param perm Permission line.
 * @return Return value indicating access status.
 *
 */
extern "C" PLUGIN_API Access HasPermission(const uint64_t id, const plg::string& perm) {
	std::shared_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v != users.end())
		return v->second.hasPermission(perm);
	return Access::NotFound;
}

/**
 * @brief Check if a user belongs to a specific group (directly or via parent groups).
 *
 * @param id Player ID.
 * @param group Group name.
 * @return True if user belongs to the group, false if user or group does not exist or user is not a member.
 */
extern "C" PLUGIN_API bool HasGroup(const uint64_t id, const plg::string& group) {
	std::shared_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end())
		return false;

	const Group* g = GetGroup(group);

	for (const auto gg: v->second._groups) {
		auto ggg = gg;
		while (ggg) {
			if (ggg == g)
				return true;
			ggg = ggg->_parent;
		}
	}
	return false;
}

/**
 * @brief Get the immunity level of a user.
 *
 * @param id Player ID.
 * @return Immunity value, or 0 if user does not exist.
 */
extern "C" PLUGIN_API int GetImmunity(const uint64_t id) {
	std::shared_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end())
		return 0;
	return v->second._immunity;
}

/**
 * @brief Add a permission to a user.
 *
 * @param id Player ID.
 * @param perm Permission line.
 * @return True if successful, false if user does not exist.
 */
extern "C" PLUGIN_API bool AddPermission(const uint64_t id, const plg::string& perm) {
	std::unique_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end())
		return false;
	v->second.nodes.addPerm(perm);
	return true;
}

/**
 * @brief Add a permissions to a user.
 *
 * @param id Player ID
 * @param perms Permissions array
 * @return True if successful, false if user does not exist
 */
extern "C" PLUGIN_API bool AddPermissions(const uint64_t id, const plg::vector<plg::string>& perms) {
	std::unique_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end())
		return false;

	for (const auto& perm: perms)
		v->second.nodes.addPerm(perm);
	return true;
}

/**
 * @brief Remove a permission from a user.
 *
 * @param id Player ID.
 * @param perm Permission line.
 * @return True if successful, false if user does not exist.
 */
extern "C" PLUGIN_API bool RemovePermission(const uint64_t id, const plg::string& perm) {
	std::unique_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end())
		return false;
	v->second.nodes.deletePerm(perm);
	return true;
}

/**
 * @brief Remove a permissions to a user.
 *
 * @param id Player ID
 * @param perms Permissions array
 * @return True if successful, false if user does not exist
 */
extern "C" PLUGIN_API bool RemovePermissions(const uint64_t id, const plg::vector<plg::string>& perms) {
	std::unique_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end())
		return false;

	for (const auto& perm: perms)
		v->second.nodes.deletePerm(perm);
	return true;
}

/**
 * @brief Add a group to a user.
 *
 * @param id Player ID.
 * @param group Group name.
 * @return True if group added, false if user/group does not exist or user is already a member.
 */
extern "C" PLUGIN_API bool AddGroup(const uint64_t id, const plg::string& group) {
	std::unique_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end())
		return false;

	Group* g = GetGroup(group);
	for (const auto gg: v->second._groups) { const Group* ggg = gg;
		while (ggg) {
			if (ggg == g)
				return false;
			ggg = ggg->_parent;
		}
	}
	v->second._groups.push_back(g);
	return true;
}

/**
 * @brief Remove a group from a user.
 *
 * @param id Player ID.
 * @param group Group name.
 * @return True if group removed, false if user/group does not exist.
 */
extern "C" PLUGIN_API bool RemoveGroup(const uint64_t id, const plg::string& group) {
	std::unique_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end())
		return false;

	Group* g = GetGroup(group);
	if (g == nullptr)
		return false;
	const auto it = v->second._groups.find(g);
	if (it == v->second._groups.end())
		return true;
	v->second._groups.erase(it);
	return true;
}

/**
 * @brief Get a cookie value for a user.
 *
 * @param id Player ID.
 * @param name Cookie name.
 * @return Cookie value, or invalid if user/cookie does not exist.
 */
extern "C" PLUGIN_API plg::any GetCookie(uint64_t id, const plg::string& name) {
	std::shared_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end())
		return plg::any(plg::invalid{});

	const auto val = v->second.cookies.find(name);
	if (val == v->second.cookies.end())
		return plg::any(plg::invalid{});
	return val->second;
}

/**
 * @brief Set a cookie value for a user.
 *
 * @param id Player ID.
 * @param name Cookie name.
 * @param cookie Cookie value.
 * @return True if successful, false if user does not exist.
 */
extern "C" PLUGIN_API bool SetCookie(uint64_t id, const plg::string& name, const plg::any& cookie) {
	std::unique_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end())
		return false;

	v->second.cookies[name] = cookie;
	return true;
}

/**
 * @brief Create a new user.
 *
 * @param id Player ID.
 * @param immunity User immunity.
 * @param lgroups Array of groups to inherit.
 * @param perms Array of permissions.
 * @return True if created, false if user already exists|parent groups does not exist.
 */
extern "C" PLUGIN_API bool CreateUser(uint64_t id, int immunity, const plg::vector<plg::string>& lgroups, const plg::vector<plg::string>& perms) {
	std::unique_lock lock(users_mtx);
	if (users.contains(id))
		return false;

	plg::vector<Group*> llgroups;
	llgroups.reserve(lgroups.size());
	for (auto& lgroup: lgroups) {
		Group* gg = GetGroup(lgroup);
		if (gg == nullptr)
			return false;
		llgroups.push_back(gg);
	}

	users.try_emplace(id, immunity, std::move(llgroups), perms);
	return true;
}

/**
 * @brief Delete a user.
 *
 * @param id Player ID.
 * @return True if deleted, false if user does not exist.
 */
extern "C" PLUGIN_API bool DeleteUser(const uint64_t id) {
	std::unique_lock lock(users_mtx);
	const auto v = users.find(id);
	if (v == users.end())
		return false;

	users.erase(v);
	return true;
}