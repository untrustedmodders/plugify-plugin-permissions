#pragma once
#include <atomic>
#include <mutex>
#include <shared_mutex>

extern std::mutex global_mutex;

/**
 * @brief Kind of change reported to permission and group callbacks.
 */
enum class Action : int32_t
{
    /// Added.
    Add = 0,
    /// Removed.
    Remove = 1,
    /// Replaced (state or duration changed).
    Replace = 2,
    /// A plain permission was replaced with its wildcard ("a" -> "a.*").
    ReplaceToWC = 3
};
