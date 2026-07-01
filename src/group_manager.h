#pragma once
#include "basic.h"
#include "group.h"
#include "user_manager.h"

#include <parallel_hashmap/phmap.h>
#include <plugin_export.h>

extern phmap::flat_hash_map<uint64_t, Group*> groups;

PLUGIFY_FORCE_INLINE Group* GetGroup(const std::string_view& name)
{
    const uint64_t hash = XXH3_64bits(name.data(), name.size());
    std::shared_lock lock(groups_mtx);
    const auto it = groups.find(hash);
    if (it == groups.end()) return nullptr;
    return it->second;
}

/**
 * @brief Callback invoked when a parent group is set for a child group.
 *
 * @param pluginID		Identifier of the plugin that initiated the call.
 * @param childName		Name of the child group.
 * @param parentName	Name of the parent group being assigned.
 */
using SetParentCallback = void (*)(const int64_t pluginID, const plg::string& childName,
                                   const plg::string& parentName);

/**
 * @brief Callback invoked when a option value is set for a group.
 *
 * @param pluginID		Identifier of the plugin that initiated the call.
 * @param groupName		Name of the group.
 * @param optionName	Name of the option being set.
 * @param value			Value of the option.
 */
using SetOptionGroupCallback = void (*)(const int64_t pluginID, const plg::string& groupName,
                                        const plg::string& optionName, const plg::any& value);

/**
 * @brief Callback invoked when a permission is added or removed from a group.
 *
 * @param pluginID      Identifier of the plugin that initiated the call.
 * @param action        Action performed (Add or Remove).
 * @param groupName 	Name of the group.
 * @param perm	        Permission line affected.
 * @param oldState      State before the change (Allow, Disallow, or PermNotFound).
 * @param newState      Current state after the change (the newly assigned state).
 */
using GroupPermissionCallback = void (*)(const int64_t pluginID, const Action action, const plg::string& groupName,
                                         const plg::string& perm, const Status oldState, const Status newState);

/**
 * @brief Callback invoked after a group is successfully created.
 *
 * @param pluginID	Identifier of the plugin that initiated the call.
 * @param name		Name of the created group.
 * @param perms		Array of permissions assigned to the group.
 * @param priority	Priority of the group.
 * @param parent	Name of the parent group (empty if none).
 */
using GroupCreateCallback = void (*)(const int64_t pluginID, const plg::string& name,
                                     const plg::vector<plg::string>& perms, const int priority,
                                     const plg::string& parent);

/**
 * @brief Callback invoked before a group is deleted.
 *
 * @param pluginID	Identifier of the plugin that initiated the call.
 * @param name		Name of the group being deleted.
 */
using GroupDeleteCallback = void (*)(const int64_t pluginID, const plg::string& name);

/**
 * @brief Called when the core requests loading of server groups.
 *
 * This callback is triggered when the system needs to load
 * group definitions associated with a specific plugin.
 * Extensions (e.g., database providers) should subscribe to
 * this event and load the groups into memory.
 *
 * @param pluginID Identifier of the plugin that initiated the call.
 */
using LoadGroupsCallback = void(*)(const int64_t pluginID);


struct SetParentCallbacks
{
    std::shared_mutex _lock;
    phmap::flat_hash_set<SetParentCallback> _callbacks;
    std::atomic_int _counter;
};

struct SetOptionGroupCallbacks
{
    std::shared_mutex _lock;
    phmap::flat_hash_set<SetOptionGroupCallback> _callbacks;
    std::atomic_int _counter;
};

struct GroupPermissionCallbacks
{
    std::shared_mutex _lock;
    phmap::flat_hash_set<GroupPermissionCallback> _callbacks;
    std::atomic_int _counter;
};

struct GroupCreateCallbacks
{
    std::shared_mutex _lock;
    phmap::flat_hash_set<GroupCreateCallback> _callbacks;
    std::atomic_int _counter;
};

struct GroupDeleteCallbacks
{
    std::shared_mutex _lock;
    phmap::flat_hash_set<GroupDeleteCallback> _callbacks;
    std::atomic_int _counter;
};

struct LoadGroupsCallbacks
{
	std::shared_mutex _lock;
	phmap::flat_hash_set<LoadGroupsCallback> _callbacks;
	std::atomic_int _counter;
};
