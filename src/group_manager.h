#pragma once
#include "basic.h"
#include "group.h"
#include "user_manager.h"

#include <parallel_hashmap/phmap.h>
#include <plugin_export.h>

struct GroupManager {
private:
	phmap::flat_hash_map<uint64_t, Group*> _groups;
	std::shared_mutex _lock;
public:
	Group* Get(const std::string_view groupName) {
		const uint64_t hash = XXH3_64bits(groupName.data(), groupName.size());
		std::shared_lock lock(_lock);

		const auto it = _groups.find(hash);
		return it == _groups.end() ? nullptr : it->second;
	}

	bool Exists(const std::string_view groupName) {
		const uint64_t hash = XXH3_64bits(groupName.data(), groupName.size());
		std::shared_lock lock(_lock);

		return _groups.contains(hash);
	}

	bool Add(const plg::vector<plg::string>& perms, const plg::string& groupName, const int priority, Group* parent) {
		const uint64_t hash = XXH3_64bits(groupName.data(), groupName.size());
		std::unique_lock lock(_lock);

		if (_groups.contains(hash))
			return false;

		_groups.emplace(hash, new Group(perms, groupName, priority, parent));
		return true;
	}

	bool Delete(const std::string_view groupName) {
		const uint64_t hash = XXH3_64bits(groupName.data(), groupName.size());
		Group* g = nullptr;
		{
			std::unique_lock lock(_lock);
			const auto it = _groups.find(hash);
			if (it == _groups.end())
				return false;
			g = it->second;
			_groups.erase(it);
		}
		// Cleanup references
		for (Group* value : _groups | std::views::values)
		{
			Group* cur_group = value;
			while (cur_group)
			{
				if (cur_group->_parent.load() == g)
				{
					cur_group->_parent.store(nullptr);
					break;
				}
				cur_group = cur_group->_parent;
			}
		}
		g_TimerSystem.CreateTimer(10, &DelayedDelete, TimerFlag::Default, {static_cast<void*>(g)});
		return true;
	}

	static void DelayedDelete(uint32_t, const plg::vector<plg::any>& params) {
		delete static_cast<Group*>(plg::get<void*>(params.at(0)));
	}

	plg::vector<plg::string> DumpAllGroups() {
		plg::vector<plg::string> lgroups;
		{
			std::shared_lock lock(_lock);
			for (const auto& vv: _groups | std::views::values)
				lgroups.push_back(vv->_name);
		}

		return lgroups;
	}
};

extern GroupManager g_GroupManager;

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
