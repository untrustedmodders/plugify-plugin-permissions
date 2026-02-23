#include "user_manager.h"

phmap::flat_hash_map<uint64_t, User> users;

std::shared_mutex users_mtx;

UserPermissionCallbacks user_permission_callbacks;

UserSetCookieCallbacks user_set_cookie_callbacks;

UserGroupCallbacks user_group_callbacks;

UserCreateCallbacks user_create_callbacks;
UserDeleteCallbacks user_delete_callbacks;

PermExpirationCallbacks perm_expiration_callbacks;
GroupExpirationCallbacks group_expiration_callbacks;

UserLoadCallbacks user_load_callbacks;

void g_PermExpirationCallback([[maybe_unused]] uint32_t timer, const plg::vector<plg::any>& userData)
{
    const plg::string* perm = &plg::get<plg::string>(userData[0]);
    const uint64_t targetID = plg::get<uint64_t>(userData[1]);
    {
        std::unique_lock lock(users_mtx);
        const auto it = users.find(targetID);
        if (it == users.end())
            return;
        it->second.temp_nodes.deletePerm(*perm);
    }

    std::shared_lock lock(perm_expiration_callbacks._lock);
    for (const auto& callback : perm_expiration_callbacks._callbacks)
        callback(targetID, *perm);
}

void g_GroupExpirationCallback(uint32_t /*timer*/, const plg::vector<plg::any>& userData)
{
    const plg::string* group_name = &plg::get<plg::string>(userData[0]);
    uint64_t targetID = plg::get<uint64_t>(userData[1]);
    {
        std::unique_lock lock(users_mtx);
        const Group* g = GetGroup(*group_name);
        if (g == nullptr)
            return;
        const auto it = users.find(targetID);
        if (it == users.end())
            return;
        if (!it->second.delGroup(g))
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
    std::shared_lock lock(users_mtx);
    const auto v = users.find(targetID);
    if (v == users.end())
        return Status::TargetUserNotFound;

    perms = dumpNode(v->second.user_nodes);
    perms.append_range(dumpNode(v->second.temp_nodes));

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
    std::shared_lock lock(users_mtx);
    const auto v1 = users.find(actorID);
    const auto v2 = users.find(targetID);
    if (v1 == users.end())
        return Status::ActorUserNotFound;
    if (v2 == users.end())
        return Status::TargetUserNotFound;

    const int i1 = v1->second.getImmunity();
    const int i2 = v2->second.getImmunity();

    return i1 >= i2 ? Status::Allow : Status::Disallow;
}

/**
 * @brief Check if a user has a specific permission.
 *
 * @param targetID Player ID.
 * @param perm Permission line.
 * @return Allow, Disallow, PermNotFound, TargetUserNotFound
 *
 */
extern "C" PLUGIN_API Status HasPermission(const uint64_t targetID, const plg::string& perm)
{
    uint16_t perm_type;
    std::shared_lock lock(users_mtx);
    const auto v = users.find(targetID);
    if (v != users.end())
        return v->second.hasPermission(perm, perm_type);
    return Status::TargetUserNotFound;
}

/**
 * @brief Check if a user belongs to a specific group (directly or via parent groups).
 *
 * @param targetID Player ID.
 * @param groupName Group name.
 * @return PermanentGroup, TemporalGroup, GroupNotDefined TargetUserNotFound, GroupNotFound
 */
extern "C" PLUGIN_API Status HasGroup(const uint64_t targetID, const plg::string& groupName)
{
    std::shared_lock lock(users_mtx);
    const auto v = users.find(targetID);
    if (v == users.end())
        return Status::TargetUserNotFound;

    const Group* g = GetGroup(groupName);
    if (g == nullptr)
        return Status::GroupNotFound;

    for (const auto& gg : v->second._groups)
    {
        auto ggg = gg.group;
        while (ggg)
        {
            if (ggg == g)
                return gg.timestamp == 0 ? Status::PermanentGroup : Status::TemporalGroup;
            ggg = ggg->_parent;
        }
    }
    return Status::GroupNotDefined;
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
    std::shared_lock lock(users_mtx);
    const auto v = users.find(targetID);
    if (v == users.end())
        return Status::TargetUserNotFound;

    outGroups.clear();
    outGroups.reserve(v->second._groups.size());
    for (const auto& g : v->second._groups)
    {
        plg::string s = g.group->_name;
        if (g.timestamp != 0)
        {
            s += ' ';
            s += plg::to_string(g.timestamp);
        }
        outGroups.push_back(std::move(s));
    }

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
    std::shared_lock lock(users_mtx);
    const auto v = users.find(targetID);
    if (v == users.end())
        return Status::TargetUserNotFound;
    immunity = v->second.getImmunity();
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
    std::shared_lock lock(users_mtx);
    const auto v = users.find(targetID);
    if (v == users.end())
        return Status::TargetUserNotFound;
    v->second._immunity = immunity;
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
extern "C" PLUGIN_API Status AddPermission(const uint64_t pluginID, const uint64_t targetID, const plg::string& perm,
                                           const time_t timestamp, const bool dontBroadcast)
{
    std::unique_lock lock(users_mtx);
    const auto v = users.find(targetID);
    if (v == users.end())
        return Status::TargetUserNotFound;

    if (!v->second.addPerm(perm, timestamp, targetID))
        return Status::PermAlreadyGranted;

    if (!dontBroadcast)
    {
        std::shared_lock lock2(user_permission_callbacks._lock);
        for (const UserPermissionCallback cb : user_permission_callbacks._callbacks)
            cb(pluginID, Action::Add, targetID, perm, timestamp);
    }
    return Status::Success;
}

/**
 * @brief Remove a permission from a user.
 *
 * @param pluginID Identifier of the plugin that calls the method.
 * @param targetID Player ID.
 * @param perm Permission line.
 * @return Success, TargetUserNotFound, PermNotFound
 */
extern "C" PLUGIN_API Status RemovePermission(const uint64_t pluginID, const uint64_t targetID, const plg::string& perm)
{
    uint16_t perm_type;
    std::unique_lock lock(users_mtx);
    const auto v = users.find(targetID);
    if (v == users.end())
        return Status::TargetUserNotFound;

    (void)v->second.hasPermission(perm, perm_type);
    if (perm_type > 1)
        return Status::PermNotFound; // Because this permission is in Groups
    {
        const time_t timestamp = perm_type == 0 ? 1 : 0;
        std::shared_lock lock2(user_permission_callbacks._lock);
        for (const UserPermissionCallback cb : user_permission_callbacks._callbacks)
            cb(pluginID, Action::Remove, targetID, perm, timestamp);
    }
    if (perm_type == 1)
        v->second.user_nodes.deletePerm(perm);
    else
        v->second.temp_nodes.deletePerm(perm);
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
extern "C" PLUGIN_API Status AddGroup(const uint64_t pluginID, const uint64_t targetID, const plg::string& groupName,
                                      const time_t timestamp, const bool dontBroadcast)
{
    std::unique_lock lock(users_mtx);
    const auto v = users.find(targetID);
    if (v == users.end())
        return Status::TargetUserNotFound;

    Group* g = GetGroup(groupName);
    if (g == nullptr)
        return Status::GroupNotFound;

    for (const auto& gg : v->second._groups)
    {
        const Group* ggg = gg.group;
        if (ggg == g)
        {
            // Reschedule
            if (gg.timestamp != timestamp)
            {
                v->second.delGroup(ggg);
                break;
            }
            return Status::GroupAlreadyExist;
        }
        ggg = ggg->_parent;
        while (ggg)
        {
            if (ggg == g)
                return Status::GroupAlreadyExist;
            ggg = ggg->_parent;
        }
    }

    v->second.addGroup(g, timestamp, targetID);

    if (!dontBroadcast)
    {
        std::shared_lock lock2(user_group_callbacks._lock);
        for (const UserGroupCallback cb : user_group_callbacks._callbacks)
            cb(pluginID, Action::Add, targetID, groupName, timestamp);
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
extern "C" PLUGIN_API Status RemoveGroup(const uint64_t pluginID, const uint64_t targetID, const plg::string& groupName)
{
    std::unique_lock lock(users_mtx);
    const auto v = users.find(targetID);
    if (v == users.end())
        return Status::TargetUserNotFound;

    Group* g = GetGroup(groupName);
    if (g == nullptr)
        return Status::ChildGroupNotFound;

    for (auto it = v->second._groups.begin(); it != v->second._groups.end(); it++)
    {
        if (it->group == g)
        {
            std::shared_lock lock2(user_group_callbacks._lock);
            for (const UserGroupCallback cb : user_group_callbacks._callbacks)
                cb(pluginID, Action::Remove, targetID, groupName, it->timestamp);
            v->second.delGroup(it->group);
            return Status::Success;
        }
    }
    return Status::ParentGroupNotFound;
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
    std::shared_lock lock(users_mtx);
    const auto v = users.find(targetID);
    if (v == users.end())
        return Status::TargetUserNotFound;

    auto val = v->second.cookies.find(name);
    bool found = val != v->second.cookies.end();
    if (!found)
    {
        // Check in groups cookies
        for (TempGroup& g : v->second._groups)
        {
            Group* gg = g.group;
            while (gg)
            {
                val = gg->cookies.find(name);
                found = val != gg->cookies.end();
                if (found)
                    break;
                gg = gg->_parent;
            }
        }
    }
    if (found)
        value = val->second;
    return found ? Status::Success : Status::CookieNotFound;
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
extern "C" PLUGIN_API Status SetCookie(const uint64_t pluginID, const uint64_t targetID, const plg::string& name,
                                       const plg::any& cookie, const bool dontBroadcast)
{
    std::unique_lock lock(users_mtx);
    const auto v = users.find(targetID);
    if (v == users.end())
        return Status::TargetUserNotFound;

    v->second.cookies[name] = cookie;
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
    std::shared_lock lock(users_mtx);
    const auto v = users.find(targetID);
    if (v == users.end())
        return Status::TargetUserNotFound;

    names.clear();
    values.clear();

    for (const auto& [kv, vv] : v->second.cookies)
    {
        names.push_back(kv);
        values.push_back(vv);
    }

    return Status::Success;
}

/**
 * @brief Create a new user.
 *
 * @param pluginID Identifier of the plugin that calls the method.
 * @param targetID Player ID.
 * @param immunity User immunity (set -1 to return highest group priority).
 * @param groupsList Array of groups to inherit ("group timestamp").
 * @param permsList Array of permissions (perm.iss.ion timestamp) or (perm.iss.ion).
 * @return Success, UserAlreadyExist, GroupNotFound, ChildGroupNotFound
 */
extern "C" PLUGIN_API Status CreateUser(const uint64_t pluginID, const uint64_t targetID, const int immunity,
                                        const plg::vector<plg::string>& groupsList,
                                        const plg::vector<plg::string>& permsList)
{
    std::unique_lock lock(users_mtx);
    if (users.contains(targetID))
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

    users.try_emplace(targetID, immunity, groupsList, permsList, targetID);
    {
        std::shared_lock lock2(user_create_callbacks._lock);
        for (const UserCreateCallback cb : user_create_callbacks._callbacks)
            cb(pluginID, targetID, immunity, groupsList, permsList);
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
extern "C" PLUGIN_API Status DeleteUser(const uint64_t pluginID, const uint64_t targetID)
{
    std::unique_lock lock(users_mtx);
    const auto v = users.find(targetID);
    if (v == users.end())
        return Status::TargetUserNotFound;

    {
        std::shared_lock lock2(user_delete_callbacks._lock);
        for (const UserDeleteCallback cb : user_delete_callbacks._callbacks)
            cb(pluginID, targetID);
    }
    Node::destroyAllTimers(v->second.temp_nodes);
    users.erase(v);
    return Status::Success;
}

/**
 * @brief Check if a user exists.
 *
 * @param targetID Player ID.
 * @return True if user exists, false otherwise.
 */
extern "C" PLUGIN_API bool UserExists(const uint64_t targetID)
{
    std::shared_lock lock(users_mtx);
    const auto v = users.find(targetID);
    return v != users.end();
}

/**
 * @brief Requests loading of a user's data.
 *
 * This function is called to initiate the user data loading process.
 * It triggers the corresponding load event so that subscribed
 * extensions (e.g., database providers) can load and initialize
 * the user's data in memory.
 *
 * The function itself does not perform any storage operations.
 * It only dispatches the load request.
 *
 * @param pluginID Identifier of the plugin that calls the method.
 * @param targetID PlayerID of the user whose data should be loaded.
 */
extern "C" PLUGIN_API void LoadUser(const uint64_t pluginID, const uint64_t targetID)
{
    std::shared_lock lock2(user_load_callbacks._lock);
    for (const UserLoadCallback cb : user_load_callbacks._callbacks)
        cb(pluginID, targetID);
}

/**
 * @brief Register listener on LoadUser event.
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnLoadUser_Register(UserLoadCallback callback)
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
extern "C" PLUGIN_API Status OnLoadUser_Unregister(UserLoadCallback callback)
{
    std::unique_lock lock(user_load_callbacks._lock);
    const size_t ret = user_load_callbacks._callbacks.erase(callback);
    return ret > 0 ? Status::Success : Status::CallbackNotFound;
}

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
