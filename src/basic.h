#pragma once
#include <mutex>
#include <shared_mutex>

extern std::mutex global_mutex;

enum class Action : int32_t
{
    Add = 0,
    Remove = 1,
    Replace = 2,
    ReplaceToWC = 3
};
