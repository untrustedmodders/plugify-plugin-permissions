#pragma once
#include "basic.h"
#include "group.h"
#include "userManager.h"

#include <mutex>

#include <plugin_export.h>

static std::unordered_map<uint64_t, Group*> groups;

inline Group* GetGroup(const plg::string& name) {
	const uint64_t hash = XXH3_64bits(name.data(), name.size());
	std::shared_lock lock(groups_mtx);
	const auto it = groups.find(hash);
	if (it == groups.end()) return nullptr;
	return it->second;
}