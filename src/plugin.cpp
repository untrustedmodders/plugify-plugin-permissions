#include <iostream>
#include <plg/plugin.hpp>
#include <plg/string.hpp>
#include <plugin_export.h>

class PlugifyPermissions final : public plg::IPluginEntry {
public:
	void OnPluginStart() override {
		std::cout << "Permissions core initialized" << std::endl;
	}

	void OnPluginEnd() override {
		std::cout << "Permissions core stopped" << std::endl;
	}

} g_permissionsPlugin;

EXPOSE_PLUGIN(PLUGIN_API, PlugifyPermissions, &g_permissionsPlugin)
