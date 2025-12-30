#include "user_manager.h"
phmap::flat_hash_map<uint64_t, User> users;

std::shared_mutex users_mtx;

PLUGIFY_WARN_PUSH()

#if defined(__clang__)
PLUGIFY_WARN_IGNORE("-Wreturn-type-c-linkage")
#elif defined(_MSC_VER)
PLUGIFY_WARN_IGNORE(4190)
#endif

/**
 * @brief Get permissions of user
 *
 * @param targetID Player ID
 * @param perms Permissions
 * @return Success, TargetUserNotFound
 */
extern "C" PLUGIN_API Status DumpPermissions(const uint64_t targetID, plg::vector<plg::string>& perms) {
	std::shared_lock lock(users_mtx);
	const auto v = users.find(targetID);
	if (v == users.end())
		return Status::TargetUserNotFound;

	perms = dumpNode(v->second.nodes);

	return Status::Success;
}

/**
 * @brief Check players immunity or groups priority
 *
 * @param actorID Player performing the action
 * @param targetID Player receiving the action
 * @return Allow, Disallow, ActorUserNotFound, or TargetUserNotFound
 */
extern "C" PLUGIN_API Status CanAffectUser(const uint64_t actorID, const uint64_t targetID) {
	std::shared_lock lock(users_mtx);
	const auto v1 = users.find(actorID);
	const auto v2 = users.find(targetID);
	if (v1 == users.end())
		return Status::ActorUserNotFound;
	if (v2 == users.end())
		return Status::TargetUserNotFound;

	const auto i1 = v1->second._immunity == -1 ? (v1->second._groups.empty() ? -1 : v1->second._groups.front()->_priority) : v1->second._immunity;
	const auto i2 = v2->second._immunity == -1 ? (v2->second._groups.empty() ? -1 : v2->second._groups.front()->_priority) : v2->second._immunity;

	return i1 >= i2 ? Status::Allow : Status::Disallow;
}

/**
 * @brief Check if a user has a specific permission.
 *
 * @param targetID Player ID.
 * @param perm Permission line.
 * @return Allow, Disallow, PermNotFound, TargetUserNotFound
 *
 */
extern "C" PLUGIN_API Status HasPermission(const uint64_t targetID, const plg::string& perm) {
	std::shared_lock lock(users_mtx);
	const auto v = users.find(targetID);
	if (v != users.end())
		return v->second.hasPermission(perm);
	return Status::TargetUserNotFound;
}

/**
 * @brief Check if a user belongs to a specific group (directly or via parent groups).
 *
 * @param targetID Player ID.
 * @param groupName Group name.
 * @return Allow, Disallow, TargetUserNotFound, GroupNotFound
 */
extern "C" PLUGIN_API Status HasGroup(const uint64_t targetID, const plg::string& groupName) {
	std::shared_lock lock(users_mtx);
	const auto v = users.find(targetID);
	if (v == users.end())
		return Status::TargetUserNotFound;

	const Group* g = GetGroup(groupName);
	if (g == nullptr)
		return Status::GroupNotFound;

	for (const auto gg: v->second._groups) {
		auto ggg = gg;
		while (ggg) {
			if (ggg == g)
				return Status::Allow;
			ggg = ggg->_parent;
		}
	}
	return Status::Disallow;
}

/**
 * @Brief Get user groups.
 *
 * @param targetID Player ID.
 * @param outGroups Groups
 * @return Success, TargetUserNotFound
 */
extern "C" PLUGIN_API Status GetUserGroups(const uint64_t targetID, plg::vector<plg::string>& outGroups) {
	std::shared_lock lock(users_mtx);
	const auto v = users.find(targetID);
	if (v == users.end())
		return Status::TargetUserNotFound;

	outGroups.clear();
	outGroups.reserve(v->second._groups.size());
	for (const auto g: v->second._groups)
		outGroups.push_back(g->_name);

	return Status::Success;
}

/**
 * @brief Get the immunity level of a user.
 *
 * @param targetID Player ID.
 * @param immunity Immunity
 * @return Success, TargetUserNotFound
 */
extern "C" PLUGIN_API Status GetImmunity(const uint64_t targetID, int& immunity) {
	std::shared_lock lock(users_mtx);
	const auto v = users.find(targetID);
	if (v == users.end())
		return Status::TargetUserNotFound;
	immunity = v->second._immunity;
	return Status::Success;
}

/**
 * @brief Add a permission to a user.
 *
 * @param targetID Player ID.
 * @param perm Permission line.
 * @return Success, TargetUserNotFound
 */
extern "C" PLUGIN_API Status AddPermission(const uint64_t targetID, const plg::string& perm) {
	std::unique_lock lock(users_mtx);
	const auto v = users.find(targetID);
	if (v == users.end())
		return Status::TargetUserNotFound;
	v->second.nodes.addPerm(perm);
	return Status::Success;
}

/**
 * @brief Add a permissions to a user.
 *
 * @param targetID Player ID
 * @param perms Permissions array
 * @return Success, TargetUserNotFound
 */
extern "C" PLUGIN_API Status AddPermissions(const uint64_t targetID, const plg::vector<plg::string>& perms) {
	std::unique_lock lock(users_mtx);
	const auto v = users.find(targetID);
	if (v == users.end())
		return Status::TargetUserNotFound;

	for (const auto& perm:
		 perms) v->second.nodes.addPerm(perm);
	return Status::Success;
}

/**
 * @brief Remove a permission from a user.
 *
 * @param targetID Player ID.
 * @param perm Permission line.
 * @return Success, TargetUserNotFound
 */
extern "C" PLUGIN_API Status RemovePermission(const uint64_t targetID, const plg::string& perm) {
	std::unique_lock lock(users_mtx);
	const auto v = users.find(targetID);
	if (v == users.end())
		return Status::TargetUserNotFound;

	v->second.nodes.deletePerm(perm);
	return Status::Success;
}

/**
 * @brief Remove a permissions to a user.
 *
 * @param targetID Player ID
 * @param perms Permissions array
 * @return Success, TargetUserNotFound
 */
extern "C" PLUGIN_API Status RemovePermissions(const uint64_t targetID, const plg::vector<plg::string>& perms) {
	std::unique_lock lock(users_mtx);
	const auto v = users.find(targetID);
	if (v == users.end())
		return Status::TargetUserNotFound;

	for (const auto& perm: perms)
		v->second.nodes.deletePerm(perm);
	return Status::Success;
}

/**
 * @brief Add a group to a user.
 *
 * @param targetID Player ID.
 * @param group Group name.
 * @return Success, TargetUserNotFound, GroupNotFound, GroupAlreadyExist
 */
extern "C" PLUGIN_API Status AddGroup(const uint64_t targetID, const plg::string& group) {
	std::unique_lock lock(users_mtx);
	const auto v = users.find(targetID);
	if (v == users.end())
		return Status::TargetUserNotFound;

	Group* g = GetGroup(group);
	if (g == nullptr)
		return Status::GroupNotFound;
	for (const auto gg: v->second._groups) {
		const Group* ggg = gg;
		while (ggg) {
			if (ggg == g)
				return Status::GroupAlreadyExist;
			ggg = ggg->_parent;
		}
	}
	v->second._groups.push_back(g);
	v->second.sortGroups();
	return Status::Success;
}

/**
 * @brief Remove a group from a user.
 *
 * @param targetID Player ID.
 * @param groupName Group name.
 * @return Success, TargetUserNotFound, ChildGroupNotFound, ParentGroupNotFound
 */
extern "C" PLUGIN_API Status RemoveGroup(const uint64_t targetID, const plg::string& groupName) {
	std::unique_lock lock(users_mtx);
	const auto v = users.find(targetID);
	if (v == users.end())
		return Status::TargetUserNotFound;

	Group* g = GetGroup(groupName);
	if (g == nullptr)
		return Status::ChildGroupNotFound;
	return plg::erase(v->second._groups, g) > 0 ? Status::Success : Status::ParentGroupNotFound;
}

/**
 * @brief Get a cookie value for a user.
 *
 * @param targetID Player ID.
 * @param name Cookie name.
 * @param value Cookie value.
 * @return Success, TargetUserNotFound, CookieNotFound
 */
extern "C" PLUGIN_API Status GetCookie(uint64_t targetID, const plg::string& name, plg::any& value) {
	std::shared_lock lock(users_mtx);
	const auto v = users.find(targetID);
	if (v == users.end())
		return Status::TargetUserNotFound;

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
		value = val->second;
	return found ? Status::Success : Status::CookieNotFound;
}

/**
 * @brief Set a cookie value for a user.
 *
 * @param targetID Player ID.
 * @param name Cookie name.
 * @param cookie Cookie value.
 * @return Success, TargetUserNotFound
 */
extern "C" PLUGIN_API Status SetCookie(uint64_t targetID, const plg::string& name, const plg::any& cookie) {
	std::unique_lock lock(users_mtx);
	const auto v = users.find(targetID);
	if (v == users.end())
		return Status::TargetUserNotFound;

	v->second.cookies[name] = cookie;
	return Status::Success;
}

/**
 * @brief Get all cookies from user.
 *
 * @param targetID Player ID.
 * @param names Array of cookie names
 * @param values Array of cookie values
 * @return Success, TargetUserNotFound
 */

extern "C" PLUGIN_API Status GetAllCookies(const uint64_t targetID, plg::vector<plg::string>& names, plg::vector<plg::any>& values) {
	std::shared_lock lock(users_mtx);
	const auto v = users.find(targetID);
	if (v == users.end())
		return Status::TargetUserNotFound;

	names.clear();
	values.clear();

	for (const auto& [kv, vv]: v->second.cookies) {
		names.push_back(kv);
		values.push_back(vv);
	}

	return Status::Success;
}

/**
 * @brief Create a new user.
 *
 * @param targetID Player ID.
 * @param immunity User immunity (set -1 to return highest group priority).
 * @param groupNames Array of groups to inherit.
 * @param perms Array of permissions.
 * @return Success, UserAlreadyExist, GroupNotFound
 */
extern "C" PLUGIN_API Status CreateUser(uint64_t targetID, int immunity, const plg::vector<plg::string>& groupNames, const plg::vector<plg::string>& perms) {
	std::unique_lock lock(users_mtx);
	if (users.contains(targetID))
		return Status::UserAlreadyExist;

	plg::vector<Group*> groupPointers;
	groupPointers.reserve(groupNames.size());
	for (auto& name: groupNames) {
		Group* group = GetGroup(name);
		if (group == nullptr)
			return Status::GroupNotFound;
		groupPointers.push_back(group);
	}

	users.try_emplace(targetID, immunity, std::move(groupPointers), perms);
	return Status::Success;
}

/**
 * @brief Delete a user.
 *
 * @param targetID Player ID.
 * @return Success, TargetUserNotFound
 */
extern "C" PLUGIN_API Status DeleteUser(const uint64_t targetID) {
	std::unique_lock lock(users_mtx);
	const auto v = users.find(targetID);
	if (v == users.end())
		return Status::TargetUserNotFound;

	users.erase(v);
	return Status::Success;
}

/**
 * @brief Check if a user exists.
 *
 * @param targetID Player ID.
 * @return True if user exists, false otherwise.
 */
extern "C" PLUGIN_API bool UserExists(const uint64_t targetID) {
	std::shared_lock lock(users_mtx);
	const auto v = users.find(targetID);
	return v != users.end();
}

PLUGIFY_WARN_POP()