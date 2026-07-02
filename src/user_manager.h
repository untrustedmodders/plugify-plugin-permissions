#pragma once
#include "basic.h"
#include "group.h"
#include "user.h"
#include "group_manager.h"

#include <plg/any.hpp>
#include <plugin_export.h>
#include <set>

struct UserManager {
private:
	phmap::flat_hash_map<uint64_t, std::shared_ptr<User>> _users;
	std::shared_mutex _lock;
public:
	std::shared_ptr<User> Get(const uint64_t targetID) {
		std::shared_lock lock(_lock);

		const auto it = _users.find(targetID);
		return it == _users.end() ? nullptr : it->second;
	}

	bool Exists(const uint64_t targetID) {
		std::shared_lock lock(_lock);

		return _users.contains(targetID);
	}

	bool Add(const uint64_t targetID, const int immunity, const bool offline, const plg::vector<plg::string>& groupsList) {
		std::unique_lock lock(_lock);

		if (_users.contains(targetID))
			return false;

		_users.emplace(targetID, std::make_shared<User>(immunity, groupsList, targetID, offline));
		return true;
	}

	bool Delete(const uint64_t targetID) {
		std::unique_lock lock(_lock);

		return _users.erase(targetID) > 0;
	}

	plg::vector<uint64_t> DumpAllUsers()
	{
		std::shared_lock lock(_lock);
		auto keys_view = std::views::keys(_users);
		return {keys_view.begin(), keys_view.end()};
	}
};

extern UserManager g_UserManager;

enum class PlayerState : uint32_t {
    NotFound = 0,
    Online = 1,
    Offline = 2,
};

/**
 * @brief Callback invoked when a permission is added, removed, or replaced for a user.
 *
 * @param pluginID      Identifier of the plugin that initiated the call.
 * @param action        Action performed (Add, Remove, or Replace).
 * @param targetID      Player ID of the affected user.
 * @param perm          Permission line affected.
 * @param oldState      State before the change (Allow, Disallow, or PermNotFound).
 * @param newState      Current state after the change (the newly assigned state).
 * @param oldTimestamp  Duration before the change (-1 if it didn't exist).
 * @param newTimestamp  New duration (timestamp) assigned to the permission.
 */
using UserPermissionCallback = void (*)(const int64_t pluginID, const Action action, const uint64_t targetID,
                                        const plg::string& perm, const Status oldState, const Status newState, const time_t oldTimestamp, const time_t newTimestamp);

/**
 * @brief Callback invoked when a cookie is set for a user.
 *
 * @param pluginID	Identifier of the plugin that initiated the call.
 * @param targetID	Player ID of the user.
 * @param name		Name of the cookie.
 * @param cookie	Value of the cookie.
 */
using UserSetCookieCallback = void (*)(const int64_t pluginID, const uint64_t targetID, const plg::string& name,
                                       const plg::any& cookie);

/**
 * @brief Callback invoked when a group is added or removed from a user.
 *
 * @param pluginID	    Identifier of the plugin that initiated the call.
 * @param action	    Action performed (Add or Remove).
 * @param targetID	    Player ID of the affected user.
 * @param group		    Name of the group added or removed.
 * @param oldTimestamp  Duration before the change (-1 if it didn't exist).
 * @param newTimestamp  New group duration.
 */
using UserGroupCallback = void (*)(const int64_t pluginID, const Action action, const uint64_t targetID,
                                   const plg::string& group, const time_t oldTimestamp, const time_t newTimestamp);

/**
 * @brief Callback invoked after a user is successfully created.
 *
 * @param pluginID		Identifier of the plugin that initiated the call.
 * @param targetID		Player ID of the created user.
 * @param immunity		User immunity value passed to CreateUser (may be -1 if highest group priority was requested).
 * @param offline       Indicates whether the user's data was loaded without user presence on server.
 * @param groupNames	Array of groups inherited by the user.
 */
using UserCreateCallback = void (*)(const int64_t pluginID, const uint64_t targetID, const int immunity,
                                    const bool offline, const plg::vector<plg::string>& groupNames);

/**
 * @brief Callback invoked before a user is deleted.
 *
 * @param pluginID	Identifier of the plugin that initiated the call.
 * @param targetID	Player ID of the user being deleted.
 */
using UserDeleteCallback = void (*)(const int64_t pluginID, const uint64_t targetID);

/**
 * @brief Callback invoked when a permission in user has been expired.
 *
 * @param targetID  Player ID of the user whose permission has expired.
 * @param perm      Permission line affected.
 * @param state     The state of the permission before expiration (Allow or Disallow).
 */
using PermExpirationCallback = void(*)(const uint64_t targetID, const plg::string& perm, const Status state);

/**
 * @brief Callback invoked when a group in user has been expired.
 *
 * @param targetID  PlayerID of the user whose group has expired.
 * @param group     Name of the group expiration.
 */
using GroupExpirationCallback = void(*)(const uint64_t targetID, const plg::string& group);

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
 * @param playerState  Indicates whether the user's data was loaded without user presence on server.
 */
using UserLoadedCallback = void(*)(const int64_t pluginID, const uint64_t targetID, const PlayerState playerState);

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
 * @param username  The user's current username. Intended for synchronizing the username with external storage (e.g. updating an existing record or setting it during initial user creation).
 * @param offline   Insdicates whether the user's data was loaded without user presence on server.
 * @param callback  Callback function to be invoked by the storage provider upon completion of the loading operation to return the retrieved data.
 */
using UserRequestCallback = void(*)(const int64_t pluginID, const uint64_t targetID, const plg::string& username, const bool offline, UserLoadedCallback callback);

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
    phmap::flat_hash_set<UserRequestCallback> _callbacks;
    std::atomic_int _counter;
};

struct UserLoadedCallbacks
{
    std::shared_mutex _lock;
    phmap::flat_hash_set<UserLoadedCallback> _callbacks;
    std::atomic_int _counter;
};
