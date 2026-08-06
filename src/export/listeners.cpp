#include "core/listeners.hpp"
#include "core/listeners_manager.hpp"

extern "C" {
    #undef DECLARE_ACCESSOR
    #define DECLARE_ACCESSOR(ApiName, CbType, VarName) \
    PLUGIN_API Status ApiName##_Register(CbType callback) { return VarName##_callbacks.Register(callback); } \
    PLUGIN_API Status ApiName##_Unregister(CbType callback) { return VarName##_callbacks.Unregister(callback); }

    LISTENER_LIST(DECLARE_ACCESSOR)
}