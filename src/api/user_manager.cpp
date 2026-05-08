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
UserLoadedCallbacks user_loaded_callbacks;

void g_PermExpirationCallback([[maybe_unused]] uint32_t timer, const plg::vector<plg::any>& userData)
{
    const plg::string* perm = &plg::get<plg::string>(userData[0]);
    const bool state = plg::get<bool>(userData[1]);
    const uint64_t targetID = plg::get<uint64_t>(userData[2]);
    plg::vector<plg::string> deleted_perms;
    {
        std::unique_lock lock(users_mtx);
        const auto it = users.find(targetID);
        if (it == users.end())
            return;
        it->second.temp_nodes.deletePerm(*perm, false, deleted_perms);
    }

    std::shared_lock lock(perm_expiration_callbacks._lock);
    for (const auto& callback : perm_expiration_callbacks._callbacks)
        for (const plg::string& s : deleted_perms)
            callback(targetID, s, state ? Status::Allow : Status::Disallow);
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

    perms = Node::dumpNode(v->second.user_nodes);
    perms.append_range(Node::dumpNode(v->second.temp_nodes));

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
 * @param exact Checking permission with ignoring wildcards (pass 'false' for default behavior)
 * @param permSource Permission source
 * @param timestamp Permission timestamp
 * @return Allow, Disallow, PermNotFound, TargetUserNotFound
 */
extern "C" PLUGIN_API Status HasPermissionExtended(const uint64_t targetID, const plg::string& perm, const bool exact,
                                                   PermSource& permSource, time_t& timestamp)
{
    timestamp = -1;
    permSource = PermSource::NotFound;
    std::shared_lock lock(users_mtx);
    const auto v = users.find(targetID);
    if (v == users.end())
        return Status::TargetUserNotFound;

    bool w_wildcard;
    const Status status = v->second.hasPermission(perm, permSource, exact, w_wildcard, timestamp);
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
 * @return PermanentGroup, TemporalGroup, GroupNotDefined, TargetUserNotFound, GroupNotFound
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

    for (const auto& temp_group : v->second._groups)
    {
        const Group* parent = temp_group.group;
        while (parent)
        {
            if (parent == g)
                return temp_group.timestamp == 0 ? Status::PermanentGroup : Status::TemporalGroup;
            parent = parent->_parent;
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

    PermSource perm_type;
    const bool denied = perm.starts_with('-');
    bool w_wildcard;
    time_t old_timestamp = -1;
    const Status oldState = v->second.hasPermission(perm, perm_type, true, w_wildcard, old_timestamp);
    bool diff = !((denied && oldState == Status::Disallow) || (!denied && oldState == Status::Allow));

    Action act = Action::Add;

    if (oldState != Status::PermNotFound) // Node is existing - check if user want to rewrite wildcard
    {
        if (diff)
            return Status::PermAlreadyGranted;

        if (w_wildcard && !isWildcard(perm))
        {
            if (timestamp == 0 && old_timestamp == 0)
                return Status::PermAlreadyGranted;
        }

        if (timestamp != 0)
        {
            if (old_timestamp == 0 || timestamp <= old_timestamp)
                return Status::PermAlreadyGranted;
        }
        else
        {
            if (old_timestamp == 0)
            {
                if (!(isWildcard(perm) && !w_wildcard))
                    return Status::PermAlreadyGranted;
            }
        }

        act = Action::Replace;
    }

    if (timestamp != 0)
    {
        v->second.addTempPerm(perm, timestamp, targetID);
    }
    else
    {
        if (perm_type == PermSource::UserTemp)
        {
            plg::vector<plg::string> deleted_perms;
            v->second.temp_nodes.deletePerm(perm, false, deleted_perms);
        }
        v->second.user_nodes.addPerm(perm);
    }

    if (!dontBroadcast)
    {
        std::shared_lock lock2(user_permission_callbacks._lock);
        for (const UserPermissionCallback cb : user_permission_callbacks._callbacks)
            cb(pluginID, act, targetID, denied ? perm.substr(1) : perm, oldState, denied ? Status::Disallow : Status::Allow, old_timestamp, timestamp);
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
extern "C" PLUGIN_API Status SetPermission(const uint64_t pluginID, const uint64_t targetID, const plg::string& perm,
                                           const time_t timestamp, const bool dontBroadcast)
{
    std::unique_lock lock(users_mtx);
    const auto v = users.find(targetID);
    if (v == users.end())
        return Status::TargetUserNotFound;

    PermSource perm_type;
    const bool denied = perm.starts_with('-');
    bool w_wildcard;
    time_t old_timestamp = -1;
    const Status oldState = v->second.hasPermission(perm, perm_type, true, w_wildcard, old_timestamp);
    bool diff = !((denied && oldState == Status::Disallow) || (!denied && oldState == Status::Allow));

    if (oldState != Status::PermNotFound) // Node is existing - check if user want to rewrite wildcard
    {
        if (!isWildcard(perm))
        {
            if (w_wildcard)
                return Status::PermAlreadyGranted;
        }
        else if (!w_wildcard)
            diff = true;
    }

    Action act = Action::Add;

    plg::vector<plg::string> deleted_perms;
    switch (perm_type)
    {
        case PermSource::UserTemp:
            if (old_timestamp == timestamp && !diff)
                return Status::PermAlreadyGranted;

            if (timestamp == 0)
                v->second.temp_nodes.deletePerm(perm, false, deleted_perms);

            act = Action::Replace;
            break;
        case PermSource::User:
            if (timestamp == 0 && !diff)
                return Status::PermAlreadyGranted;

            if (timestamp != 0)
                v->second.user_nodes.deletePerm(perm, false, deleted_perms);

            act = Action::Replace;
            break;
        default:
            break;
    }

    if (timestamp != 0)
        v->second.addTempPerm(perm, timestamp, targetID);
    else
        v->second.user_nodes.addPerm(perm);

    if (!dontBroadcast)
    {
        std::shared_lock lock2(user_permission_callbacks._lock);
        for (const UserPermissionCallback cb : user_permission_callbacks._callbacks)
            cb(pluginID, act, targetID, denied ? perm.substr(1) : perm, oldState, denied ? Status::Disallow : Status::Allow, old_timestamp, timestamp);
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
extern "C" PLUGIN_API Status RemovePermission(const uint64_t pluginID, const uint64_t targetID, const plg::string& perm,
                                              const bool recursiveDeletion)
{
    PermSource perm_type;
    std::unique_lock lock(users_mtx);
    const auto v = users.find(targetID);
    if (v == users.end())
        return Status::TargetUserNotFound;

    bool w_wildcard;
    time_t old_timestamp = -1;
    const auto oldState = v->second.hasPermission(perm, perm_type, true, w_wildcard, old_timestamp);
    if (perm_type > PermSource::User)
        return Status::PermNotFound; // Because this permission is in Groups, or not found at all

    plg::vector<plg::string> deleted_perms;
    if (perm_type == PermSource::User)
        v->second.user_nodes.deletePerm(perm, recursiveDeletion, deleted_perms);
    else
        v->second.temp_nodes.deletePerm(perm, recursiveDeletion, deleted_perms);

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
extern "C" PLUGIN_API Status AddGroup(const uint64_t pluginID, const uint64_t targetID, const plg::string& groupName,
                                      const time_t timestamp, const bool dontBroadcast)
{
    std::unique_lock lock(users_mtx);
    const auto v = users.find(targetID);
    if (v == users.end())
        return Status::TargetUserNotFound;

    Group* req_group = GetGroup(groupName);
    if (req_group == nullptr)
        return Status::GroupNotFound;

    time_t old_timestamp = -1;
    Action act = Action::Add;

    for (const auto& temp_group : v->second._groups)
    {
        const Group* parent = temp_group.group;
        if (parent == req_group)
        {
            // Reschedule
            if (temp_group.timestamp != timestamp)
            {
                old_timestamp = temp_group.timestamp;
                v->second.delGroup(parent);
                act = Action::Replace;
                break;
            }
            return Status::GroupAlreadyExist;
        }
        parent = parent->_parent;
        while (parent)
        {
            if (parent == req_group)
                return Status::GroupAlreadyExist;
            parent = parent->_parent;
        }
    }

    v->second.addGroup(req_group, timestamp, targetID);

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
                cb(pluginID, Action::Remove, targetID, groupName, it->timestamp, 0);
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
            Group* parent = g.group;
            while (parent)
            {
                val = parent->cookies.find(name);
                found = val != parent->cookies.end();
                if (found)
                    break;
                parent = parent->_parent;
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
 */
extern "C" PLUGIN_API void LoadUser(const uint64_t pluginID, const uint64_t targetID, const plg::string& username)
{
    std::shared_lock lock2(user_load_callbacks._lock);
    for (const UserLoadCallback cb : user_load_callbacks._callbacks)
        cb(pluginID, targetID, username);
}

/**
 * @brief Dispatches a user-loaded event.
 *
 * Invoked by a storage provider to indicate that the requested
 * user data loading process has completed successfully.
 *
 * After this call, the user is considered fully initialized.
 *
 * @param pluginID Identifier of the storage plugin reporting completion.
 * @param targetID PlayerID of the loaded user.
 */
extern "C" PLUGIN_API void LoadedUser(const uint64_t pluginID, const uint64_t targetID)
{
    std::shared_lock lock2(user_loaded_callbacks._lock);
    for (const UserLoadedCallback cb : user_loaded_callbacks._callbacks)
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
 * @brief Register listener on LoadedUser event.
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnLoadedUser_Register(UserLoadedCallback callback)
{
    std::unique_lock lock(user_loaded_callbacks._lock);
    auto ret = user_loaded_callbacks._callbacks.insert(callback);
    return ret.second ? Status::Success : Status::CallbackAlreadyExist;
}

/**
 * @brief Unregister listener on LoadedUser event.
 *
 * @param callback Function callback.
 * @return
 */
extern "C" PLUGIN_API Status OnLoadedUser_Unregister(UserLoadedCallback callback)
{
    std::unique_lock lock(user_loaded_callbacks._lock);
    const size_t ret = user_loaded_callbacks._callbacks.erase(callback);
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
