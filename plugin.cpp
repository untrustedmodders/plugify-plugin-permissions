#include <iostream>
#include <plugify/cpp_plugin.hpp>
#include <plugify/string.hpp>
#include <plugin_export.h>

class PlugifyPermissions final : public plg::IPluginEntry {
public:
	void OnPluginStart() override {
		std::cout << "Permissions core initialized" << std::endl;
	}

	void OnPluginEnd() override {
		std::cout << "Permissions core stopped" << std::endl;
	}

} g_examplePlugin;

EXPOSE_PLUGIN(PLUGIN_API, PlugifyPermissions, &g_examplePlugin)
