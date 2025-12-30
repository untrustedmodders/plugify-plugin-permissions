#include <print>
#include <plg/plugin.hpp>
#include <plg/string.hpp>
#include <plugin_export.h>

class PlugifyPermissions final : public plg::IPluginEntry {
public:
	void OnPluginStart() override {
		std::println("Permissions core initialized");
	}

	void OnPluginEnd() override {
		std::println("Permissions core stopped");
	}

} g_permissionsPlugin;

EXPOSE_PLUGIN(PLUGIN_API, PlugifyPermissions, &g_permissionsPlugin)
