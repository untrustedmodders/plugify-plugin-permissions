#pragma once
#include <shared_mutex>

static std::shared_mutex users_mtx, groups_mtx;