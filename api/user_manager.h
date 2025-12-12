#pragma once
#include "basic.h"
#include "group.h"
#include "group_manager.h"
#include "user.h"

#include <mutex>
#include <plg/any.hpp>
#include <plugin_export.h>

extern phmap::flat_hash_map<uint64_t, User> users;

inline void GroupManager_Callback(const Group* group) {
	// Delete group from all users
	std::unique_lock lock(users_mtx);
	for (auto& value: users | std::views::values) {
		plg::erase(value._groups, group);
	}
}