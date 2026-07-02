#include "user_manager.h"

UserManager g_UserManager;

UserPermissionCallbacks user_permission_callbacks;

UserSetCookieCallbacks user_set_cookie_callbacks;

UserGroupCallbacks user_group_callbacks;

UserCreateCallbacks user_create_callbacks;
UserDeleteCallbacks user_delete_callbacks;

PermExpirationCallbacks perm_expiration_callbacks;
GroupExpirationCallbacks group_expiration_callbacks;

UserLoadCallbacks user_load_callbacks;
// UserLoadedCallbacks user_loaded_callbacks;

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
    for (const auto& callback : perm_expiration_callbacks._callbacks)
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
    for (const auto& callback : group_expiration_callbacks._callbacks)
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
 * @param targetID Player ID.
 * @param immunity Immunity
 * @return Success, TargetUserNotFound
 */
extern "C" PLUGIN_API Status SetImmunity(const uint64_t targetID, const int immunity)
{
	const std::shared_ptr<User> s_user = g_UserManager.Get(targetID);
	if (s_user == nullptr)
		return Status::TargetUserNotFound;
    s_user->_immunity = immunity;
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
		return Status::Error;
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

    if (!dontBroadcast)
    {
        if (replaceToWC) {
	        act = Action::ReplaceToWC;
        	if (timestamp != old_timestamp && timestamp == 0)
        		s_user->delTempPerm(std::string_view(perm).substr(0, perm.length() - 2), false, deleted_perms);
        }
    	const plg::string prm = denied ? perm.substr(1) : perm;
        std::shared_lock lock2(user_permission_callbacks._lock);
        for (const UserPermissionCallback cb : user_permission_callbacks._callbacks)
            cb(pluginID, act, targetID, prm, oldState, denied ? Status::Disallow : Status::Allow, old_timestamp, timestamp);
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
		return Status::Error;
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

    plg::vector<plg::string> deleted_perms;
    switch (perm_type)
    {
        case PermSource::UserTemp:
            if (old_timestamp == timestamp && !diff)
                return Status::PermAlreadyGranted;

            if (timestamp == 0)
                s_user->delTempPerm(perm, false, deleted_perms);

            act = Action::Replace;
            break;
        case PermSource::User:
            if (timestamp == 0 && !diff)
                return Status::PermAlreadyGranted;

            if (timestamp != 0)
                s_user->delTempPerm(perm, false, deleted_perms);

            act = Action::Replace;
            break;
        default:
            break;
    }

    s_user->addPerm(perm, timestamp, targetID);

    if (!dontBroadcast)
    {
        if (replaceToWC)
            act = Action::ReplaceToWC;
    	const plg::string prm = denied ? perm.substr(1) : perm;
        std::shared_lock lock2(user_permission_callbacks._lock);
        for (const UserPermissionCallback cb : user_permission_callbacks._callbacks)
            cb(pluginID, act, targetID, prm, oldState, denied ? Status::Disallow : Status::Allow, old_timestamp, timestamp);
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
                                              const bool recursiveDeletion)
{
	if (perm.empty())
		return Status::Error;
    PermSource perm_type;
	const std::shared_ptr<User> s_user = g_UserManager.Get(targetID);
	if (s_user == nullptr)
		return Status::TargetUserNotFound;

    bool w_wildcard;
    time_t old_timestamp = -1;
    const auto oldState = s_user->hasPermission(perm, perm_type, true, w_wildcard, old_timestamp);
    if (perm_type > PermSource::User)
        return Status::PermNotFound; // Because this permission is in Groups, or not found at all

    plg::vector<plg::string> deleted_perms;
	bool ret;
    if (perm_type == PermSource::User)
        ret = s_user->delPerm(perm, recursiveDeletion, deleted_perms);
    else
        ret = s_user->delTempPerm(perm, recursiveDeletion, deleted_perms);
	if (!ret)
		return Status::PermNotFound;

    {
        std::shared_lock lock2(user_permission_callbacks._lock);
        for (const UserPermissionCallback cb : user_permission_callbacks._callbacks)
            for (const plg::string& s : deleted_perms)
                cb(pluginID, Action::Remove, targetID, s, oldState, Status::PermNotFound, old_timestamp, 0);
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
		return Status::Error;
	const std::shared_ptr<User> s_user = g_UserManager.Get(targetID);
	if (s_user == nullptr)
		return Status::TargetUserNotFound;

	std::scoped_lock lock(global_mutex);

    Group* req_group = g_GroupManager.Get(groupName);
    if (req_group == nullptr)
        return Status::GroupNotFound;

    time_t old_timestamp = -1;
    Action act = Action::Add;

	{
		bool parent;
		Status stats = s_user->hasGroup(req_group, old_timestamp, parent);
		if (stats != Status::GroupNotDefined) {
			if (parent)
				return Status::GroupAlreadyExist;
			if (old_timestamp != timestamp) {
				s_user->delGroup(req_group, old_timestamp);
				act = Action::Replace;
			}
			else
				return Status::GroupAlreadyExist;
		}
	}

    s_user->addGroup(req_group, timestamp, targetID);

    if (!dontBroadcast)
    {
        std::shared_lock lock2(user_group_callbacks._lock);
        for (const UserGroupCallback cb : user_group_callbacks._callbacks)
            cb(pluginID, act, targetID, groupName, old_timestamp, timestamp);
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
extern "C" PLUGIN_API Status RemoveGroup(const int64_t pluginID, const uint64_t targetID, const plg::string& groupName)
{
	if (groupName.empty())
		return Status::Error;
	const std::shared_ptr<User> s_user = g_UserManager.Get(targetID);
	if (s_user == nullptr)
		return Status::TargetUserNotFound;

    Group* g = g_GroupManager.Get(groupName);
    if (g == nullptr)
        return Status::ChildGroupNotFound;

	time_t timestamp;
	if (!s_user->delGroup(g, timestamp))
		return Status::ParentGroupNotFound;

    {
        std::shared_lock lock2(user_group_callbacks._lock);
        for (const UserGroupCallback cb : user_group_callbacks._callbacks)
            cb(pluginID, Action::Remove, targetID, groupName, timestamp, 0);
        return Status::Success;
    }
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
		return Status::Error;
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
		return Status::Error;
	const std::shared_ptr<User> s_user = g_UserManager.Get(targetID);
	if (s_user == nullptr)
		return Status::TargetUserNotFound;

    s_user->setCookie(name, cookie);
    if (!dontBroadcast)
    {
        std::shared_lock lock2(user_set_cookie_callbacks._lock);
        for (const UserSetCookieCallback cb : user_set_cookie_callbacks._callbacks)
            cb(pluginID, targetID, name, cookie);
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
        std::shared_lock lock2(user_create_callbacks._lock);
        for (const UserCreateCallback cb : user_create_callbacks._callbacks)
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
    const auto s_user = g_UserManager.Get(targetID);
    if (s_user == nullptr)
        return Status::TargetUserNotFound;

    {
        std::shared_lock lock2(user_delete_callbacks._lock);
        for (const UserDeleteCallback cb : user_delete_callbacks._callbacks)
            cb(pluginID, targetID);
    }

	g_UserManager.Delete(targetID);
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
	const auto s_user = g_UserManager.Get(targetID);
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
 * @param callback   Callback function to be invoked by the storage provider upon completion of the loading operation to return the retrieved data.
 */
extern "C" PLUGIN_API void LoadUser(const int64_t pluginID, const uint64_t targetID, const plg::string& username, const bool offline, UserLoadedCallback callback)
{
    std::shared_lock lock2(user_load_callbacks._lock);
    for (const UserRequestCallback cb : user_load_callbacks._callbacks)
        cb(pluginID, targetID, username, offline, callback);
}

// /**
//  * @brief Dispatches a user-loaded event.
//  *
//  * Invoked by a storage provider to indicate that the requested
//  * user data loading process has completed successfully.
//  *
//  * After this call, the user is considered fully initialized.
//  *
//  * @param pluginID Identifier of the storage plugin reporting completion.
//  * @param targetID PlayerID of the loaded user.
//  */
// extern "C" PLUGIN_API void LoadedUser(const int64_t pluginID, const uint64_t targetID)
// {
//     std::shared_lock lock2(user_loaded_callbacks._lock);
//     for (const UserLoadedCallback cb : user_loaded_callbacks._callbacks)
//         cb(pluginID, targetID);
// }

/**
 * @brief Register listener on LoadUser event.
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnLoadUser_Register(UserRequestCallback callback)
{
    std::unique_lock lock(user_load_callbacks._lock);
    auto ret = user_load_callbacks._callbacks.insert(callback);
    return ret.second ? Status::Success : Status::CallbackAlreadyExist;
}

/**
 * @brief Unregister listener on LoadUser event.
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnLoadUser_Unregister(UserRequestCallback callback)
{
    std::unique_lock lock(user_load_callbacks._lock);
    const size_t ret = user_load_callbacks._callbacks.erase(callback);
    return ret > 0 ? Status::Success : Status::CallbackNotFound;
}

// /**
//  * @brief Register listener on LoadedUser event.
//  *
//  * @param callback Function callback.
//  * @return
//  */
// extern "C" PLUGIN_API Status OnLoadedUser_Register(UserLoadedCallback callback)
// {
//     std::unique_lock lock(user_loaded_callbacks._lock);
//     auto ret = user_loaded_callbacks._callbacks.insert(callback);
//     return ret.second ? Status::Success : Status::CallbackAlreadyExist;
// }
//
// /**
//  * @brief Unregister listener on LoadedUser event.
//  *
//  * @param callback Function callback.
//  * @return
//  */
// extern "C" PLUGIN_API Status OnLoadedUser_Unregister(UserLoadedCallback callback)
// {
//     std::unique_lock lock(user_loaded_callbacks._lock);
//     const size_t ret = user_loaded_callbacks._callbacks.erase(callback);
//     return ret > 0 ? Status::Success : Status::CallbackNotFound;
// }

/**
 * @brief Register listener on user permission add/remove
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnUserPermissionChange_Register(UserPermissionCallback callback)
{
    std::unique_lock lock(user_permission_callbacks._lock);
    auto ret = user_permission_callbacks._callbacks.insert(callback);
    return ret.second ? Status::Success : Status::CallbackAlreadyExist;
}

/**
 * @brief Unregister listener on user permission add/remove
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnUserPermissionChange_Unregister(UserPermissionCallback callback)
{
    std::unique_lock lock(user_permission_callbacks._lock);
    const size_t ret = user_permission_callbacks._callbacks.erase(callback);
    return ret > 0 ? Status::Success : Status::CallbackNotFound;
}

/**
 * @brief Register listener on user cookie sets
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnUserSetCookie_Register(UserSetCookieCallback callback)
{
    std::unique_lock lock(user_set_cookie_callbacks._lock);
    auto ret = user_set_cookie_callbacks._callbacks.insert(callback);
    return ret.second ? Status::Success : Status::CallbackAlreadyExist;
}

/**
 * @brief Register listener on user cookie sets
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnUserSetCookie_Unregister(UserSetCookieCallback callback)
{
    std::unique_lock lock(user_set_cookie_callbacks._lock);
    const size_t ret = user_set_cookie_callbacks._callbacks.erase(callback);
    return ret > 0 ? Status::Success : Status::CallbackNotFound;
}

/**
 * @brief Register listener on user groups changing
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnUserGroupChange_Register(UserGroupCallback callback)
{
    std::unique_lock lock(user_group_callbacks._lock);
    auto ret = user_group_callbacks._callbacks.insert(callback);
    return ret.second ? Status::Success : Status::CallbackAlreadyExist;
}

/**
 * @brief Unregister listener on user groups changing
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnUserGroupChange_Unregister(UserGroupCallback callback)
{
    std::unique_lock lock(user_group_callbacks._lock);
    const size_t ret = user_group_callbacks._callbacks.erase(callback);
    return ret > 0 ? Status::Success : Status::CallbackNotFound;
}

/**
 * @brief Register listener on user creation
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnUserCreate_Register(UserCreateCallback callback)
{
    std::unique_lock lock(user_create_callbacks._lock);
    auto ret = user_create_callbacks._callbacks.insert(callback);
    return ret.second ? Status::Success : Status::CallbackAlreadyExist;
}

/**
 * @brief Unregister listener on user creation
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnUserCreate_Unregister(UserCreateCallback callback)
{
    std::unique_lock lock(user_create_callbacks._lock);
    const size_t ret = user_create_callbacks._callbacks.erase(callback);
    return ret > 0 ? Status::Success : Status::CallbackNotFound;
}

/**
 * @brief Register listener on user deletion
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnUserDelete_Register(UserDeleteCallback callback)
{
    std::unique_lock lock(user_delete_callbacks._lock);
    auto ret = user_delete_callbacks._callbacks.insert(callback);
    return ret.second ? Status::Success : Status::CallbackAlreadyExist;
}

/**
 * @brief Unregister listener on user deletion
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnUserDelete_Unregister(UserDeleteCallback callback)
{
    std::unique_lock lock(user_delete_callbacks._lock);
    const size_t ret = user_delete_callbacks._callbacks.erase(callback);
    return ret > 0 ? Status::Success : Status::CallbackNotFound;
}

/**
 * @brief Register listener on user permission expiration
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnPermissionExpirationCallback_Register(PermExpirationCallback callback)
{
    std::unique_lock lock(perm_expiration_callbacks._lock);
    auto ret = perm_expiration_callbacks._callbacks.insert(callback);
    return ret.second ? Status::Success : Status::CallbackAlreadyExist;
}

/**
 * @brief Unregister listener on user permission expiration
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnPermissionExpirationCallback_Unregister(PermExpirationCallback callback)
{
    std::unique_lock lock(perm_expiration_callbacks._lock);
    const size_t ret = perm_expiration_callbacks._callbacks.erase(callback);
    return ret > 0 ? Status::Success : Status::CallbackNotFound;
}

/**
 * @brief Register listener on user permission expiration
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnGroupExpirationCallback_Register(GroupExpirationCallback callback)
{
    std::unique_lock lock(group_expiration_callbacks._lock);
    auto ret = group_expiration_callbacks._callbacks.insert(callback);
    return ret.second ? Status::Success : Status::CallbackAlreadyExist;
}

/**
 * @brief Unregister listener on user group expiration
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnGroupExpirationCallback_Unregister(GroupExpirationCallback callback)
{
    std::unique_lock lock(group_expiration_callbacks._lock);
    const size_t ret = group_expiration_callbacks._callbacks.erase(callback);
    return ret > 0 ? Status::Success : Status::CallbackNotFound;
}

PLUGIFY_WARN_POP()
