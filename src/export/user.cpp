#include "core/user_manager.h"
#include "core/listeners.h"

#include <oneapi/tbb/detail/_template_helpers.h>


UserManager g_UserManager;

void g_PermExpirationCallback([[maybe_unused]] uint32_t timer, const plg::vector<plg::any>& userData)
{
    const plg::string* perm = &plg::get<plg::string>(userData[0]);
    const bool state = plg::get<bool>(userData[1]);
    const uint64_t targetID = plg::get<uint64_t>(userData[2]);
    plg::vector<plg::string> deleted_perms;
    {
    	std::shared_ptr<User> s_user = g_UserManager.Get(targetID);
    	if (s_user == nullptr)
    		return;
        s_user->delTempPerm(*perm, false, deleted_perms);
    }

    std::shared_lock lock(perm_expiration_callbacks._lock);
    for (const auto& callback : perm_expiration_callbacks._callbacks | std::views::values)
        for (const plg::string& s : deleted_perms)
            callback(targetID, s, state ? Status::Allow : Status::Disallow);
}

void g_GroupExpirationCallback(uint32_t /*timer*/, const plg::vector<plg::any>& userData)
{
    const plg::string* group_name = &plg::get<plg::string>(userData[0]);
	const uint64_t targetID = plg::get<uint64_t>(userData[1]);
    {
        const Group* g = g_GroupManager.Get(*group_name);
        if (g == nullptr)
            return;
        std::shared_ptr<User> s_user = g_UserManager.Get(targetID);
        if (s_user == nullptr)
            return;
    	time_t old_timestamp;
        if (!s_user->delGroup(g, old_timestamp))
            return;
    }

    std::shared_lock lock(group_expiration_callbacks._lock);
    for (const auto& callback : group_expiration_callbacks._callbacks | std::views::values)
        callback(targetID, *group_name);
}

PLUGIFY_WARN_PUSH()

#if defined(__clang__)
PLUGIFY_WARN_IGNORE ("-Wreturn-type-c-linkage")
#elif defined(_MSC_VER)
PLUGIFY_WARN_IGNORE (4190)
#endif

/**
 * @brief Get permissions of user
 *
 * @param targetID Player ID
 * @param perms Permissions
 * @return Success, TargetUserNotFound
 */
extern "C" PLUGIN_API Status DumpPermissions(const uint64_t targetID, plg::vector<plg::string>& perms)
{
	const std::shared_ptr<User> s_user = g_UserManager.Get(targetID);
	if (s_user == nullptr)
		return Status::TargetUserNotFound;

	perms = s_user->dumpPerms();

    return Status::Success;
}

/**
 * @brief Check players immunity or groups priority
 *
 * @param actorID Player performing the action
 * @param targetID Player receiving the action
 * @return Allow, Disallow, ActorUserNotFound, or TargetUserNotFound
 */
extern "C" PLUGIN_API Status CanAffectUser(const uint64_t actorID, const uint64_t targetID)
{
	const std::shared_ptr<User> sa_user = g_UserManager.Get(actorID);
	const std::shared_ptr<User> st_user = g_UserManager.Get(targetID);
	if (sa_user == nullptr)
		return Status::ActorUserNotFound;
	if (st_user == nullptr)
		return Status::TargetUserNotFound;

    return sa_user->_immunity >= st_user->_immunity ? Status::Allow : Status::Disallow;
}

/**
 * @brief Check if a user has a specific permission.
 *
 * @param targetID Player ID.
 * @param perm Permission line.
 * @param exact Checking permission with ignoring wildcards (pass 'false' for default behavior).
 * @param permSource Permission source.
 * @param timestamp Permission timestamp.
 * @return Allow, Disallow, PermNotFound, TargetUserNotFound
 */
extern "C" PLUGIN_API Status HasPermissionExtended(const uint64_t targetID, const plg::string& perm, const bool exact,
                                                   PermSource& permSource, time_t& timestamp)
{
    timestamp = -1;
    permSource = PermSource::NotFound;

	const std::shared_ptr<User> s_user = g_UserManager.Get(targetID);
	if (s_user == nullptr)
		return Status::TargetUserNotFound;

    if (perm.empty())
        return Status::Allow;

    bool w_wildcard;
    const Status status = s_user->hasPermission(perm, permSource, exact, w_wildcard, timestamp);
    if (exact && isWildcard(perm) != w_wildcard)
        return Status::PermNotFound;
    return status;
}

/**
 * @brief Check if a user has a specific permission.
 *
 * @param targetID Player ID.
 * @param perm Permission line.
 * @return Allow, Disallow, PermNotFound, TargetUserNotFound
 */
extern "C" PLUGIN_API Status HasPermission(const uint64_t targetID, const plg::string& perm)
{
    PermSource permSource = PermSource::NotFound;
    time_t timestamp;
    return HasPermissionExtended(targetID, perm, false, permSource, timestamp);
}

/**
 * @brief Check if a user belongs to a specific group (directly or via parent groups).
 *
 * @param targetID Player ID.
 * @param groupName Group name.
 * @param timestamp Group timestamp.
 * @return PermanentGroup, TemporalGroup, GroupNotDefined, TargetUserNotFound, GroupNotFound
 */
extern "C" PLUGIN_API Status HasGroupExtended(const uint64_t targetID, const plg::string& groupName, time_t& timestamp)
{
    timestamp = -1;
	bool parent;
	const std::shared_ptr<User> s_user = g_UserManager.Get(targetID);
	if (s_user == nullptr)
		return Status::TargetUserNotFound;

    const Group* g = g_GroupManager.Get(groupName);
    if (g == nullptr)
        return Status::GroupNotFound;

    return s_user->hasGroup(g, timestamp, parent);
}

/**
 * @brief Check if a user belongs to a specific group (directly or via parent groups).
 *
 * @param targetID Player ID.
 * @param groupName Group name.
 * @return PermanentGroup, TemporalGroup, GroupNotDefined, TargetUserNotFound, GroupNotFound
 */
extern "C" PLUGIN_API Status HasGroup(const uint64_t targetID, const plg::string& groupName)
{
    time_t timestamp;
    return HasGroupExtended(targetID, groupName, timestamp);
}

/**
 * @Brief Get user groups.
 *
 * @param targetID Player ID.
 * @param outGroups Groups
 * @return Success, TargetUserNotFound
 */
extern "C" PLUGIN_API Status GetUserGroups(const uint64_t targetID, plg::vector<plg::string>& outGroups)
{
	const std::shared_ptr<User> s_user = g_UserManager.Get(targetID);
	if (s_user == nullptr)
		return Status::TargetUserNotFound;

    s_user->dumpGroups(outGroups);

    return Status::Success;
}

/**
 * @brief Get the immunity level of a user.
 *
 * @param targetID Player ID.
 * @param immunity Immunity
 * @return Success, TargetUserNotFound
 */
extern "C" PLUGIN_API Status GetImmunity(const uint64_t targetID, int& immunity)
{
	const std::shared_ptr<User> s_user = g_UserManager.Get(targetID);
	if (s_user == nullptr)
		return Status::TargetUserNotFound;
    immunity = s_user->getImmunity();
    return Status::Success;
}

/**
 * @brief Set the immunity level of a user.
 *
 * @param pluginID Identifier of the plugin that calls the method.
 * @param targetID Player ID.
 * @param immunity Immunity.
 * @param dontBroadcast
 * @return Success, TargetUserNotFound
 */
extern "C" PLUGIN_API Status SetImmunity(const int64_t pluginID, const uint64_t targetID, const int immunity, const bool dontBroadcast)
{
	const std::shared_ptr<User> s_user = g_UserManager.Get(targetID);
	if (s_user == nullptr)
		return Status::TargetUserNotFound;

	{
		std::shared_lock lock2(user_immunity_storage_callbacks._lock);
		for (const auto& cb : user_immunity_storage_callbacks._callbacks | std::views::values) {
			if (cb && !cb(pluginID, targetID, immunity))
				return Status::DBNotReady;
		}
	}

    s_user->_immunity = immunity;

	if (!dontBroadcast) {
		std::shared_lock lock2(user_immunity_callbacks._lock);
		for (const auto& cb : user_immunity_callbacks._callbacks | std::views::values) {
			cb(pluginID, targetID, immunity);
		}
	}

    return Status::Success;
}

/**
 * @brief Add a permission to a user.
 *
 * @param pluginID Identifier of the plugin that calls the method.
 * @param targetID Player ID.
 * @param perm Permission line.
 * @param timestamp Permission duration
 * @param dontBroadcast If set to `true`, suppresses dispatching of the permission change event to registered UserPermission listeners. The permission is still applied internally.
 * @return Success, TargetUserNotFound, PermAlreadyGranted
 */
extern "C" PLUGIN_API Status AddPermission(const int64_t pluginID, const uint64_t targetID, const plg::string& perm,
                                           const time_t timestamp, const bool dontBroadcast)
{
	if (perm.empty())
		return Status::Success;
	const std::shared_ptr<User> s_user = g_UserManager.Get(targetID);
	if (s_user == nullptr)
		return Status::TargetUserNotFound;

    PermSource perm_type;
    const bool denied = perm.starts_with('-');
    bool w_wildcard;
    time_t old_timestamp = -1;
    const Status oldState = s_user->hasPermission(perm, perm_type, true, w_wildcard, old_timestamp);
    bool diff = !((denied && oldState == Status::Disallow) || (!denied && oldState == Status::Allow));

    bool replaceToWC = false;

    Action act = Action::Add;

    if (oldState != Status::PermNotFound) // Node is existing - check if user want to rewrite wildcard
    {
		if (diff)
            return Status::PermAlreadyGranted;

		if (!isWildcard(perm))
        {
            if (w_wildcard)
                return Status::PermAlreadyGranted;
        }
		else if (!w_wildcard)
        {
            replaceToWC = true;
        }

        if (timestamp != 0)
        {
            if (old_timestamp == 0 || old_timestamp >= timestamp)
                return Status::PermAlreadyGranted;
        }
        else if (old_timestamp == 0 && !replaceToWC)
            return Status::PermAlreadyGranted;

        act = Action::Replace;
    	if (replaceToWC)
    		act = Action::ReplaceToWC;
    }

	const plg::string prm = denied ? perm.substr(1) : perm;
	{
		std::shared_lock lock2(user_permission_storage_callbacks._lock);
		for (const auto& cb : user_permission_storage_callbacks._callbacks | std::views::values) {
			if (cb && !cb(pluginID, act, targetID, prm, oldState, denied ? Status::Disallow : Status::Allow, old_timestamp, timestamp))
				return Status::DBNotReady;
		}
	}

	plg::vector<plg::string> deleted_perms;

	if (timestamp != 0)
		s_user->addPerm(perm, timestamp, targetID);
	else
	{
		if (perm_type == PermSource::UserTemp)
			s_user->delTempPerm(perm, false, deleted_perms);
		s_user->addPerm(perm, 0, 0);
	}

	if (replaceToWC && timestamp != old_timestamp && timestamp == 0)
		s_user->delTempPerm(std::string_view(perm).substr(0, perm.length() - 2), false, deleted_perms);

	if (!dontBroadcast) {
		std::shared_lock lock2(user_permission_callbacks._lock);
		for (const auto& cb : user_permission_callbacks._callbacks | std::views::values) {
			cb(pluginID, act, targetID, prm, oldState, denied ? Status::Disallow : Status::Allow, old_timestamp, timestamp);
		}
	}

    return Status::Success;
}

/**
 * @brief Set a permission to a user.
 *
 * @param pluginID Identifier of the plugin that calls the method.
 * @param targetID Player ID.
 * @param perm Permission line.
 * @param timestamp Permission duration
 * @param dontBroadcast If set to `true`, suppresses dispatching of the permission change event to registered UserPermission listeners. The permission is still applied internally.
 * @return Success, TargetUserNotFound, PermAlreadyGranted
 */
extern "C" PLUGIN_API Status SetPermission(const int64_t pluginID, const uint64_t targetID, const plg::string& perm,
                                           const time_t timestamp, const bool dontBroadcast)
{
	if (perm.empty())
		return Status::Success;

	const std::shared_ptr<User> s_user = g_UserManager.Get(targetID);
	if (s_user == nullptr)
		return Status::TargetUserNotFound;

    PermSource perm_type;
    const bool denied = perm.starts_with('-');
    bool w_wildcard;
    time_t old_timestamp = -1;
    const Status oldState = s_user->hasPermission(perm, perm_type, true, w_wildcard, old_timestamp);
    bool diff = !((denied && oldState == Status::Disallow) || (!denied && oldState == Status::Allow));

    bool replaceToWC = false;

    if (oldState != Status::PermNotFound) // Node is existing - check if user want to rewrite wildcard
    {
        if (!isWildcard(perm))
        {
            if (w_wildcard)
                return Status::PermAlreadyGranted;
        }
        else if (!w_wildcard)
        {
            replaceToWC = true;
            diff = true;
        }
    }

    Action act = Action::Add;

	switch (perm_type)
    {
        case PermSource::UserTemp:
            if (old_timestamp == timestamp && !diff)
                return Status::PermAlreadyGranted;
            act = Action::Replace;
            break;
        case PermSource::User:
            if (timestamp == 0 && !diff)
                return Status::PermAlreadyGranted;
            act = Action::Replace;
            break;
        default:
            break;
    }

	if (replaceToWC)
		act = Action::ReplaceToWC;

	const plg::string prm = denied ? perm.substr(1) : perm;

	{
		std::shared_lock lock2(user_permission_storage_callbacks._lock);
		for (const auto& cb : user_permission_storage_callbacks._callbacks | std::views::values) {
			if (cb && !cb(pluginID, act, targetID, prm, oldState, denied ? Status::Disallow : Status::Allow, old_timestamp, timestamp))
				return Status::DBNotReady;
		}
	}

	if (act == Action::Replace || act == Action::ReplaceToWC) {
		plg::vector<plg::string> deleted_perms;
		switch (perm_type)
		{
			case PermSource::UserTemp:
				if (timestamp == 0)
					s_user->delTempPerm(perm, false, deleted_perms);
				break;
			case PermSource::User:
				if (timestamp != 0)
					s_user->delPerm(perm, false, deleted_perms);
				break;
			default:
				break;
		}
	}

	s_user->addPerm(perm, timestamp, targetID);
	if (!dontBroadcast) {
		std::shared_lock lock2(user_permission_callbacks._lock);
		for (const auto& cb : user_permission_callbacks._callbacks | std::views::values) {
			cb(pluginID, act, targetID, prm, oldState, denied ? Status::Disallow : Status::Allow, old_timestamp, timestamp);
		}
	}

    return Status::Success;
}

/**
 * @brief Remove a permission from a user.
 *
 * @param pluginID Identifier of the plugin that calls the method.
 * @param targetID Player ID.
 * @param perm Permission line.
 * @param recursiveDeletion Delete all nested perms.
 * @return Success, TargetUserNotFound, PermNotFound
 */
extern "C" PLUGIN_API Status RemovePermission(const int64_t pluginID, const uint64_t targetID, const plg::string& perm,
                                              const bool recursiveDeletion, const bool dontBroadcast)
{
	if (perm.empty())
		return Status::Success;
    PermSource perm_type;

	const std::shared_ptr<User> s_user = g_UserManager.Get(targetID);
	if (s_user == nullptr)
		return Status::TargetUserNotFound;

    bool w_wildcard;
    time_t old_timestamp = -1;
    const auto oldState = s_user->hasPermission(perm, perm_type, true, w_wildcard, old_timestamp);
    if (perm_type > PermSource::User)
        return Status::PermNotFound; // Because this permission is in Groups, or not found at all

	{
		std::shared_lock lock2(user_permission_storage_callbacks._lock);
		for (const auto& cb : user_permission_storage_callbacks._callbacks | std::views::values) {
			if (cb && !cb(pluginID, Action::Remove, targetID, perm, oldState, Status::PermNotFound, old_timestamp, 0))
				return Status::DBNotReady;
		}
	}

	plg::vector<plg::string> deleted_perms;
	bool ret;
	if (perm_type == PermSource::User)
		ret = s_user->delPerm(perm, recursiveDeletion, deleted_perms);
	else
		ret = s_user->delTempPerm(perm, recursiveDeletion, deleted_perms);
	// if (!ret)
	// 	return Status::PermNotFound;

	if (!dontBroadcast) {
		std::shared_lock lock2(user_permission_callbacks._lock);
		for (const auto& cb : user_permission_callbacks._callbacks | std::views::values) {
			for (const plg::string& s : deleted_perms)
				cb(pluginID, Action::Remove, targetID, s, oldState, Status::PermNotFound, old_timestamp, 0);
		}
	}

	return Status::Success;
}

/**
 * @brief Add a group to a user.
 *
 * @param pluginID Identifier of the plugin that calls the method.
 * @param targetID Player ID.
 * @param groupName Group name.
 * @param timestamp Group duration.
 * @param dontBroadcast If set to `true`, suppresses dispatching of the group change event to registered UserGroup listeners. The group is still applied internally.
 * @return Success, TargetUserNotFound, GroupNotFound, GroupAlreadyExist
 */
extern "C" PLUGIN_API Status AddGroup(const int64_t pluginID, const uint64_t targetID, const plg::string& groupName,
                                      const time_t timestamp, const bool dontBroadcast)
{
	if (groupName.empty())
		return Status::Success;

	const std::shared_ptr<User> s_user = g_UserManager.Get(targetID);
	if (s_user == nullptr)
		return Status::TargetUserNotFound;

	std::scoped_lock lock(global_mutex);

    Group* req_group = g_GroupManager.Get(groupName);
    if (req_group == nullptr)
        return Status::GroupNotFound;

	time_t old_timestamp = -1;
    Action act = Action::Add;
	bool delete_temp = false;

	{
		bool parent;
		const Status stats = s_user->hasGroup(req_group, old_timestamp, parent);
		if (stats != Status::GroupNotDefined) {
			if (parent)
				return Status::GroupAlreadyExist;
			if (old_timestamp != timestamp) {
				delete_temp = true;
				act = Action::Replace;
			}
			else
				return Status::GroupAlreadyExist;
		}
	}

	{
		std::shared_lock lock2(user_group_storage_callbacks._lock);
		for (const auto& cb : user_group_storage_callbacks._callbacks | std::views::values) {
			if (cb && !cb(pluginID, act, targetID, groupName, old_timestamp, timestamp))
				return Status::DBNotReady;
		}
	}

	if (delete_temp)
		s_user->delGroup(req_group, old_timestamp);

	s_user->addGroup(req_group, timestamp, targetID);
	if (!dontBroadcast)
	{
		std::shared_lock lock2(user_group_callbacks._lock);
		for (const auto& cb : user_group_callbacks._callbacks | std::views::values) {
			cb(pluginID, act, targetID, groupName, old_timestamp, timestamp);
		}
	}

	return Status::Success;
}

/**
 * @brief Remove a group from a user.
 *
 * @param pluginID Identifier of the plugin that calls the method.
 * @param targetID Player ID.
 * @param groupName Group name.
 * @return Success, TargetUserNotFound, ChildGroupNotFound, ParentGroupNotFound
 */
extern "C" PLUGIN_API Status RemoveGroup(const int64_t pluginID, const uint64_t targetID, const plg::string& groupName, const bool dontBroadcast)
{
	if (groupName.empty())
		return Status::Success;

	const std::shared_ptr<User> s_user = g_UserManager.Get(targetID);
	if (s_user == nullptr)
		return Status::TargetUserNotFound;

    Group* g = g_GroupManager.Get(groupName);
    if (g == nullptr)
        return Status::ChildGroupNotFound;

	time_t timestamp;
	bool parent = false;
	Status s = s_user->hasGroup(g, timestamp, parent);
	if (s == Status::GroupNotDefined || parent)
		return Status::ParentGroupNotFound;

	{
		std::shared_lock lock2(user_group_storage_callbacks._lock);
		for (const auto& cb : user_group_storage_callbacks._callbacks | std::views::values) {
			if (cb && !cb(pluginID, Action::Remove, targetID, groupName, timestamp, 0))
				return Status::DBNotReady;
		}
	}

	s_user->delGroup(g, timestamp);

	if (!dontBroadcast) {
		std::shared_lock lock2(user_group_callbacks._lock);
		for (const auto& cb : user_group_callbacks._callbacks | std::views::values) {
			cb(pluginID, Action::Remove, targetID, groupName, timestamp, 0);
		}
	}

	return Status::Success;
}

/**
 * @brief Get a cookie value for a user.
 *
 * @param targetID Player ID.
 * @param name Cookie name.
 * @param value Cookie value.
 * @return Success, TargetUserNotFound, CookieNotFound
 */
extern "C" PLUGIN_API Status GetCookie(const uint64_t targetID, const plg::string& name, plg::any& value)
{
	if (name.empty())
		return Status::Success;
	const std::shared_ptr<User> s_user = g_UserManager.Get(targetID);
	if (s_user == nullptr)
		return Status::TargetUserNotFound;

	const bool val = s_user->getCookie(name, value);

    return val ? Status::Success : Status::CookieNotFound;
}

/**
 * @brief Set a cookie value for a user.
 *
 * @param pluginID Identifier of the plugin that calls the method.
 * @param targetID Player ID.
 * @param name Cookie name.
 * @param cookie Cookie value.
 * @param dontBroadcast If set to `true`, suppresses dispatching of the cookie change event to registered UserSetCookie listeners. The cookie is still applied internally.
 * @return Success, TargetUserNotFound
 */
extern "C" PLUGIN_API Status SetCookie(const int64_t pluginID, const uint64_t targetID, const plg::string& name,
                                       const plg::any& cookie, const bool dontBroadcast)
{
	if (name.empty())
		return Status::Success;
	const std::shared_ptr<User> s_user = g_UserManager.Get(targetID);
	if (s_user == nullptr)
		return Status::TargetUserNotFound;

	{
		std::shared_lock lock2(user_cookie_storage_callbacks._lock);
		for (const auto& cb : user_cookie_storage_callbacks._callbacks | std::views::values) {
			if (cb && !cb(pluginID, targetID, name, cookie))
				return Status::DBNotReady;
		}
	}

	s_user->setCookie(name, cookie);

	if (!dontBroadcast) {
		std::shared_lock lock2(user_cookie_callbacks._lock);
		for (const auto& cb : user_cookie_callbacks._callbacks | std::views::values) {
			cb(pluginID, targetID, name, cookie);
		}
	}

    return Status::Success;
}

/**
 * @brief Get all cookies from user.
 *
 * @param targetID Player ID.
 * @param names Array of cookie names
 * @param values Array of cookie values
 * @return Success, TargetUserNotFound
 */
extern "C" PLUGIN_API Status GetAllCookies(const uint64_t targetID, plg::vector<plg::string>& names,
                                           plg::vector<plg::any>& values)
{
	const std::shared_ptr<User> s_user = g_UserManager.Get(targetID);
	if (s_user == nullptr)
		return Status::TargetUserNotFound;

	s_user->dumpCookies(names, values);

    return Status::Success;
}

/**
 * @brief Create a new user.
 *
 * @param pluginID Identifier of the plugin that calls the method.
 * @param targetID Player ID.
 * @param immunity User immunity (set -1 to return highest group priority).
 * @param offline Create as fake player.
 * @param groupsList Array of groups to inherit ("group timestamp").
 * @return Success, UserAlreadyExist, GroupNotFound, ChildGroupNotFound
 */
extern "C" PLUGIN_API Status CreateUser(const int64_t pluginID, const uint64_t targetID, const int immunity,
                                        const bool offline, const plg::vector<plg::string>& groupsList)
{
    std::scoped_lock lock(global_mutex);

    if (g_UserManager.Exists(targetID))
        return Status::UserAlreadyExist;

    for (auto& name : groupsList)
    {
        std::string_view sv = name;
        if (sv.contains(' '))
            sv = sv.substr(0, sv.find(' '));
        const Group* group = GetGroup(sv);
        if (group == nullptr)
            return Status::GroupNotFound;
    }

    g_UserManager.Add(targetID, immunity, offline, groupsList);
    {
        std::shared_lock lock2(user_create_storage_callbacks._lock);
        for (const UserCreateStorageCallback cb : user_create_storage_callbacks._callbacks | std::views::values)
            cb(pluginID, targetID, immunity, offline, groupsList);
    }

    return Status::Success;
}

/**
 * @brief Delete a user.
 *
 * @param pluginID Identifier of the plugin that calls the method.
 * @param targetID Player ID.
 * @return Success, TargetUserNotFound
 */
extern "C" PLUGIN_API Status DeleteUser(const int64_t pluginID, const uint64_t targetID)
{
	std::scoped_lock lock(global_mutex);
    if (!g_UserManager.Exists(targetID))
        return Status::TargetUserNotFound;

	g_UserManager.Delete(targetID);
	{
		std::shared_lock lock2(user_delete_storage_callbacks._lock);
		for (const UserDeleteStorageCallback cb : user_delete_storage_callbacks._callbacks | std::views::values)
			cb(pluginID, targetID);
	}

    return Status::Success;
}

/**
 * @brief Check if a user exists.
 *
 * @param targetID Player ID.
 * @return PlayerState::NotFound, PlayerState::Online, PlayerState::Offline
 */
extern "C" PLUGIN_API PlayerState UserExists(const uint64_t targetID)
{
	const std::shared_ptr<User> s_user = g_UserManager.Get(targetID);
    if (s_user != nullptr)
        return s_user->_offline ? PlayerState::Offline : PlayerState::Online;

    return PlayerState::NotFound;
}

/**
 * @brief Returns a list of IDs for all players registered in the core.
 *
 * @return A vector containing all registered player IDs.
 */
extern "C" PLUGIN_API plg::vector<uint64_t> DumpUsersList()
{
    return g_UserManager.DumpAllUsers();
}

/**
 * @brief Dispatches a request to load user data.
 *
 * Notifies all registered listeners that the specified user's data
 * should be loaded from an external storage provider.
 *
 * This function does not perform any storage operations by itself.
 * It only broadcasts the load request event.
 *
 * @param pluginID   Identifier of the calling plugin.
 * @param targetID   PlayerID of the user to be loaded.
 * @param username   The user's current username. Intended for synchronizing the username with external storage (e.g. updating an existing record or setting it during initial user creation).
 * @param offline    Indicates whether the user's data was loaded without user presence on server.
 * @param dontBroadcast
 *
 */
extern "C" Status LoadUser(const int64_t pluginID, const uint64_t targetID, const plg::string& username, const bool offline, const bool dontBroadcast)
{
	{
		std::shared_lock lock2(user_request_callbacks._lock);
		if (user_request_callbacks._callbacks.empty())
			return Status::DBNotReady;
		for (const auto& cb : user_request_callbacks._callbacks | std::views::values) {
			if (cb && !cb(pluginID, targetID, username, offline))
				return Status::DBNotReady;
		}
	}

	if (!dontBroadcast) {
		std::shared_lock lock2(user_loaded_callbacks._lock);
		for (const auto& cb : user_loaded_callbacks._callbacks | std::views::values) {
			cb(pluginID, targetID, offline ? PlayerState::Offline : PlayerState::Online);
		}
	}

	return Status::Success;
}

PLUGIFY_WARN_POP()
