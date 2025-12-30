#pragma once
#include <mutex>
#include <shared_mutex>

extern std::shared_mutex users_mtx, groups_mtx;