#pragma once
#include "group.h"
#include "user.h"
#include "basic.h"
#include "groupManager.h"

#include <mutex>
#include <plugin_export.h>
#include <plugify/any.hpp>
static std::unordered_map<uint64_t, User> users;

PLUGIFY_FORCE_INLINE void GroupManager_Callback(const Group* group) {
	// Delete group from all users
	std::unique_lock lock(users_mtx);
	for (auto& value: users | std::views::values) {
		if (auto it = value._groups.find(const_cast<Group*>(group)); it != value._groups.end())
			value._groups.erase(it);
	}
}