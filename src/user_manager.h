#pragma once
#include "basic.h"
#include "group.h"
#include "user.h"
#include "group_manager.h"

#include <plg/any.hpp>
#include <plugin_export.h>
#include <set>

extern phmap::flat_hash_map<uint64_t, User> users;

inline void GroupManager_Callback(const Group* group) {
	// Delete group from all users
	std::unique_lock lock(users_mtx);
	for (auto& value: users | std::views::values) {
		plg::erase(value._groups, group);
	}
}

using UserPermissionCallback = void (*)(const bool action, const uint64_t targetID, const plg::string& perm);
using UserPermissionsCallback = void (*)(const bool action, const uint64_t targetID, const plg::vector<plg::string>& perms);

using UserSetCookieCallback = void (*)(const uint64_t targetID, const plg::string& name, const plg::any& cookie);

using UserGroupCallback = void (*)(const bool action, const uint64_t targetID, const plg::string& group);
using UserCallback = void (*)(const bool action, const uint64_t targetID, int immunity, const plg::vector<plg::string>& groupNames, const plg::vector<plg::string>& perms);

struct UserPermissionCallbacks
{
	std::shared_mutex _lock;
	phmap::flat_hash_set<UserPermissionCallback> _callbacks;
	std::atomic_int _counter;
};
struct UserPermissionsCallbacks
{
	std::shared_mutex _lock;
	phmap::flat_hash_set<UserPermissionsCallback> _callbacks;
	std::atomic_int _counter;
};

struct UserSetCookieCallbacks
{
	std::shared_mutex _lock;
	phmap::flat_hash_set<UserSetCookieCallback> _callbacks;
	std::atomic_int _counter;
};

struct UserGroupCallbacks
{
	std::shared_mutex _lock;
	phmap::flat_hash_set<UserGroupCallback> _callbacks;
	std::atomic_int _counter;
};
struct UserCallbacks
{
	std::shared_mutex _lock;
	phmap::flat_hash_set<UserCallback> _callbacks;
	std::atomic_int _counter;
};