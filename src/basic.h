#pragma once
#include <atomic>
#include <mutex>
#include <shared_mutex>

extern std::mutex global_mutex;

extern std::atomic<int64_t> storageID;

enum class Action : int32_t
{
    Add = 0,
    Remove = 1,
    Replace = 2,
    ReplaceToWC = 3
};
