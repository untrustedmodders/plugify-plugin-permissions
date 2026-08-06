#pragma once

#include "basic.h"
#include "group.h"
#include "user.h"
#include "user_manager.h"
#include "group_manager.h"

#include <plg/any.hpp>

template<typename Func>
struct CallbackManager {
    std::shared_mutex _lock;
    phmap::flat_hash_map<int64_t, Func> _callbacks;
    std::atomic_int _counter;
};

#define CALLBACK_LIST(X) \
    /* Storage */ \
    /* User */ \
    X(OnUserRequest, UserRequestCallback, user_request) \
    X(OnUserLoaded, UserLoadedCallback, user_loaded) \
    X(OnUserImmunityChangeStorage, UserImmunityStorageCallback, user_immunity_storage) \
    X(OnUserPermissionChangeStorage, UserPermissionStorageCallback, user_permission_storage) \
    X(OnUserCookieChangeStorage, UserCookieStorageCallback, user_cookie_storage) \
    X(OnUserGroupChangeStorage, UserGroupStorageCallback, user_group_storage) \
    X(OnUserCreateStorage, UserCreateStorageCallback, user_create_storage) \
    X(OnUserDeleteStorage, UserDeleteStorageCallback, user_delete_storage) \
    /* Group */ \
    X(OnSetParentStorage, SetParentStorageCallback, set_parent_storage) \
    X(OnGroupOptionChangeStorage, GroupOptionStorageCallback, group_option_storage) \
    X(OnGroupPermissionChangeStorage, GroupPermissionStorageCallback, group_permission_storage) \
    X(OnGroupCreateStorage, GroupCreateStorageCallback, group_create_storage) \
    X(OnGroupDeleteStorage, GroupDeleteStorageCallback, group_delete_storage) \
    /* Notification */ \
    /* User */ \
    X(OnUserImmunity, UserImmunityCallback, user_immunity) \
    X(OnUserPermission, UserPermissionCallback, user_permission) \
    X(OnUserCookie, UserCookieCallback, user_cookie) \
    X(OnUserGroup, UserGroupCallback, user_group) \
    X(OnUserCreate, UserCreateCallback, user_create) \
    X(OnUserDelete, UserDeleteCallback, user_delete) \
    X(OnPermissionExpiration, PermExpirationCallback, perm_expiration) \
    X(OnGroupExpiration, GroupExpirationCallback, group_expiration) \
    /* Group */ \
    X(OnSetParent, SetParentCallback, set_parent) \
    X(OnGroupOption, GroupOptionCallback, group_option) \
    X(OnGroupPermission, GroupPermissionCallback, group_permission) \
    X(OnGroupCreate, GroupCreateCallback, group_create) \
    X(OnGroupDelete, GroupDeleteCallback, group_delete) \
    X(OnGroupsLoad, LoadGroupsCallback, load_groups)


#define DECLARE_CALLBACK_MANAGER(ApiName, CbType, VarName) \
extern CallbackManager<CbType> VarName##_callbacks;

CALLBACK_LIST(DECLARE_CALLBACK_MANAGER)
#undef DECLARE_CALLBACK_MANAGER