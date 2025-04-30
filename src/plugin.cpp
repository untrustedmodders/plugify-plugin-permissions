#include "plugin.hpp"
#include <plugify_permissions_export.h>

namespace plugperm {
	Permissions plugin;
}// namespace plugperm

EXPOSE_PLUGIN(PLUGIFY_PERMISSIONS_API, plugperm::Permissions, &plugperm::plugin)
