#pragma once
#include "basic.h"
#include "group.h"
#include "userManager.h"

#include <mutex>

#include <plugin_export.h>

static std::unordered_map<uint64_t, Group*> groups;

extern "C" Group* GetGroup(const plg::string& name);