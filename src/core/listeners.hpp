#pragma once

#include "basic.hpp"
#include "group.hpp"
#include "user_manager.hpp"
#include "group_manager.hpp"
#include "listeners_manager.hpp"

#include <plg/any.hpp>

#define LISTENER_LIST(X) \
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
    X(OnUserImmunityChange, UserImmunityCallback, user_immunity) \
    X(OnUserPermissionChange, UserPermissionCallback, user_permission) \
    X(OnUserCookieChange, UserCookieCallback, user_cookie) \
    X(OnUserGroupChange, UserGroupCallback, user_group) \
    X(OnUserCreate, UserCreateCallback, user_create) \
    X(OnUserDelete, UserDeleteCallback, user_delete) \
    X(OnPermissionExpiration, PermExpirationCallback, perm_expiration) \
    X(OnGroupExpiration, GroupExpirationCallback, group_expiration) \
    /* Group */ \
    X(OnSetParent, SetParentCallback, set_parent) \
    X(OnGroupOptionChange, GroupOptionCallback, group_option) \
    X(OnGroupPermissionChange, GroupPermissionCallback, group_permission) \
    X(OnGroupCreate, GroupCreateCallback, group_create) \
    X(OnGroupDelete, GroupDeleteCallback, group_delete) \
    X(OnGroupsLoad, LoadGroupsCallback, load_groups)


extern "C" {
#define DECLARE_ACCESSOR(ApiName, CbType, VarName) \
    static constexpr const char VarName##_name[] = #VarName; \
    inline ListenerManager<VarName##_name, CbType> VarName##_callbacks;

    LISTENER_LIST(DECLARE_ACCESSOR)
}
#undef DECLARE_ACCESSOR
