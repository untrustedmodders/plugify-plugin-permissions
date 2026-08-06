#include "core/listeners.h"

#define DEFINE_CALLBACK_MANAGER(ApiName, CbType, VarName) \
    CallbackManager<CbType> VarName##_callbacks;

CALLBACK_LIST(DEFINE_CALLBACK_MANAGER)

extern "C" {
    #undef DEFINE_REGISTER_FUNCTIONS
    #define DEFINE_REGISTER_FUNCTIONS(ApiName, CbType, VarName) \
    PLUGIN_API Status ApiName##_Register(const int64_t pluginID, CbType callback) { \
        std::unique_lock lock(VarName##_callbacks._lock); \
        auto ret = VarName##_callbacks._callbacks.insert({pluginID, callback}); \
        return ret.second ? Status::Success : Status::CallbackAlreadyExist; \
    } \
    \
    PLUGIN_API Status ApiName##_Unregister(const int64_t pluginID) { \
        std::unique_lock lock(VarName##_callbacks._lock); \
        const size_t ret = VarName##_callbacks._callbacks.erase(pluginID); \
        return ret > 0 ? Status::Success : Status::CallbackNotFound; \
    }

    CALLBACK_LIST(DEFINE_REGISTER_FUNCTIONS)
}