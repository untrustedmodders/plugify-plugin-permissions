#pragma once
#include "basic.h"
#include "group.h"
#include "user_manager.h"

#include <parallel_hashmap/phmap.h>
#include <plugin_export.h>

extern phmap::flat_hash_map<uint64_t, Group*> groups;

inline Group* GetGroup(const plg::string& name) {
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::shared_lock lock(groups_mtx);
	const auto it = groups.find(hash);
	if (it == groups.end()) return nullptr;
	return it->second;
}

using SetParentCallback = void (*)(const plg::string& childName, const plg::string& parentName);
using SetCookieGroupCallback = void (*)(const plg::string& groupName, const plg::string& cookieName, const plg::any& value);

using GroupPermissionCallback = void (*)(const bool action, const plg::string& name, const plg::string& groupName);
using GroupCallback = void (*)(const bool action, const plg::string& name, const plg::vector<plg::string>& perms, const int priority, const plg::string& parent);

struct SetParentCallbacks
{
	std::shared_mutex _lock;
	phmap::flat_hash_set<SetParentCallback> _callbacks;
	std::atomic_int _counter;
};
struct SetCookieGroupCallbacks
{
	std::shared_mutex _lock;
	phmap::flat_hash_set<SetCookieGroupCallback> _callbacks;
	std::atomic_int _counter;
};

struct GroupPermissionCallbacks
{
	std::shared_mutex _lock;
	phmap::flat_hash_set<GroupPermissionCallback> _callbacks;
	std::atomic_int _counter;
};
struct GroupCallbacks
{
	std::shared_mutex _lock;
	phmap::flat_hash_set<GroupCallback> _callbacks;
	std::atomic_int _counter;
};