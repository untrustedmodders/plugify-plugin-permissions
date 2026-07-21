#include <print>
#include <plg/plugin.hpp>
#include <plg/string.hpp>
#include <plugin_export.h>
#include "timer_system.h"
#include <atomic>

std::mutex global_mutex;
std::atomic<int64_t> connectorID = -1;

class PlugifyPermissions final : public plg::Plugin
{
public:
    plg::PluginResult OnPluginStart() override
    {
        std::println("Permissions core initialized");
		return {};
    }

    plg::PluginResult OnPluginEnd() override
    {
        std::println("Permissions core stopped");
		return {};
    }

    plg::PluginResult OnPluginUpdate(std::chrono::milliseconds) override
    {
        g_TimerSystem.RunFrame();
		return {};
    }
} g_permissionsPlugin;

extern "C" PLUGIN_API void SetConnectorID(const int64_t pluginID) {
	connectorID.store(pluginID);
}

extern "C" PLUGIN_API void ResetConnectorID() {
	connectorID.store(-1);
}

PLUGIFY_PLUGIN(PLUGIN_API, &g_permissionsPlugin)


