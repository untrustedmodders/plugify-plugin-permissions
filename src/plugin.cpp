#include <print>
#include <plg/plugin.hpp>
#include <plg/string.hpp>
#include <plugin_export.h>
#include "timer_system.h"

std::mutex global_mutex;

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

PLUGIFY_PLUGIN(PLUGIN_API, &g_permissionsPlugin)
