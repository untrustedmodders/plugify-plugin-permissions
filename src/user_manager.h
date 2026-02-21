#pragma once
#include "basic.h"
#include "group.h"
#include "user.h"
#include "group_manager.h"

#include <plg/any.hpp>
#include <plugin_export.h>
#include <set>

extern phmap::flat_hash_map<uint64_t, User> users;

inline void GroupManager_Callback(const Group* group)
{
    // Delete group from all users
    std::unique_lock lock(users_mtx);
    for (auto& value : users | std::views::values)
    {
        plg::erase(value._groups, group);
    }
}

/**
 * @brief Callback invoked when a permission is added or removed for a user.
 *
 * @param pluginID	Identifier of the plugin that initiated the call.
 * @param action	Action performed (Add or Remove).
 * @param targetID	Player ID of the affected user.
 * @param perm		Permission line affected.
 * @param timestamp Permission duration.
 */
using UserPermissionCallback = void (*)(const uint64_t pluginID, const Action action, const uint64_t targetID,
                                        const plg::string& perm, const time_t timestamp);

/**
 * @brief Callback invoked when a cookie is set for a user.
 *
 * @param pluginID	Identifier of the plugin that initiated the call.
 * @param targetID	Player ID of the user.
 * @param name		Name of the cookie.
 * @param cookie	Value of the cookie.
 */
using UserSetCookieCallback = void (*)(const uint64_t pluginID, const uint64_t targetID, const plg::string& name,
                                       const plg::any& cookie);

/**
 * @brief Callback invoked when a group is added or removed from a user.
 *
 * @param pluginID	Identifier of the plugin that initiated the call.
 * @param action	Action performed (Add or Remove).
 * @param targetID	Player ID of the affected user.
 * @param group		Name of the group added or removed.
 * @param timestamp Group duration
 */
using UserGroupCallback = void (*)(const uint64_t pluginID, const Action action, const uint64_t targetID,
                                   const plg::string& group, const time_t timestamp);

/**
 * @brief Callback invoked after a user is successfully created.
 *
 * @param pluginID		Identifier of the plugin that initiated the call.
 * @param targetID		Player ID of the created user.
 * @param immunity		User immunity value passed to CreateUser (may be -1 if highest group priority was requested).
 * @param groupNames	Array of groups inherited by the user.
 * @param perms			Array of permissions assigned to the user.
 */
using UserCreateCallback = void (*)(const uint64_t pluginID, const uint64_t targetID, int immunity,
                                    const plg::vector<plg::string>& groupNames, const plg::vector<plg::string>& perms);

/**
 * @brief Callback invoked before a user is deleted.
 *
 * @param pluginID		Identifier of the plugin that initiated the call.
 * @param targetID	Player ID of the user being deleted.
 */
using UserDeleteCallback = void (*)(const uint64_t pluginID, const uint64_t targetID);

/**
 * @brief Callback invoked when a permission in user has been expired.
 *
 * @param targetID Player ID of the user whose permission has expired.
 * @param perm Permission line affected.
 */
using PermExpirationCallback = void(*)(const uint64_t targetID, const plg::string& perm);

/**
 * @brief Callback invoked when a group in user has been expired.
 *
 * @param targetID PlayerID of the user whose group has expired.
 * @param group		Name of the group expiration.
 */
using GroupExpirationCallback = void(*)(const uint64_t targetID, const plg::string& group);

/**
 * @brief Called when a user data load is requested.
 *
 * This callback is triggered by the core when it requires
 * user data to be loaded from an external storage (e.g. database).
 * Extensions can subscribe to this event to perform the actual
 * loading process and initialize the user in memory.
 * This event does NOT guarantee that the user object already exists in memory.
 *
 * @param pluginID	Identifier of the plugin that initiated the call.
 * @param targetID	PlayerID of the user whose data should be loaded.
 */
using UserLoadCallback = void(*)(const uint64_t pluginID, const uint64_t targetID);

/**
 * @brief Called when a user's data has been fully loaded.
 *
 * This callback is triggered after a storage extension has completed
 * loading and applying the user's persistent data (e.g. groups,
 * permissions, metadata).
 *
 * At this stage, the user is considered fully initialized and ready
 * for normal operation within the system.
 *
 * @param pluginID Identifier of the plugin that reports the completion of the loading process.
 * @param targetID PlayerID of the user whose data has been loaded.
 */
using UserLoadedCallback = void(*)(const uint64_t pluginID, const uint64_t targetID);

struct UserPermissionCallbacks
{
    std::shared_mutex _lock;
    phmap::flat_hash_set<UserPermissionCallback> _callbacks;
    std::atomic_int _counter;
};

struct UserSetCookieCallbacks
{
    std::shared_mutex _lock;
    phmap::flat_hash_set<UserSetCookieCallback> _callbacks;
    std::atomic_int _counter;
};

struct UserGroupCallbacks
{
    std::shared_mutex _lock;
    phmap::flat_hash_set<UserGroupCallback> _callbacks;
    std::atomic_int _counter;
};

struct UserCreateCallbacks
{
    std::shared_mutex _lock;
    phmap::flat_hash_set<UserCreateCallback> _callbacks;
    std::atomic_int _counter;
};

struct UserDeleteCallbacks
{
    std::shared_mutex _lock;
    phmap::flat_hash_set<UserDeleteCallback> _callbacks;
    std::atomic_int _counter;
};

struct PermExpirationCallbacks
{
    std::shared_mutex _lock;
    phmap::flat_hash_set<PermExpirationCallback> _callbacks;
    std::atomic_int _counter;
};

struct GroupExpirationCallbacks
{
    std::shared_mutex _lock;
    phmap::flat_hash_set<GroupExpirationCallback> _callbacks;
    std::atomic_int _counter;
};

struct UserLoadCallbacks
{
    std::shared_mutex _lock;
    phmap::flat_hash_set<UserLoadCallback> _callbacks;
    std::atomic_int _counter;
};

struct UserLoadedCallbacks
{
    std::shared_mutex _lock;
    phmap::flat_hash_set<UserLoadedCallback> _callbacks;
    std::atomic_int _counter;
};
