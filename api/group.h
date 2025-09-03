#pragma once
#include "node.h"
#include "plugify/vector.hpp"
#include <plugify/string.hpp>

#include "xxhash.h"
#include "plugify/any.hpp"

struct Group {
	Group* _parent;// root of this group
	plg::string _name;// name of group
	int _priority;// priority of group
	std::unordered_map<plg::string, plg::any, string_hash, std::equal_to<>> cookies;// group cookies
	Node _nodes;// nodes of group

	Group(const plg::vector<plg::string>& perms, const plg::string& name, const int priority, Group* parent = nullptr) {
		this->_name = name;
		this->_nodes = loadNode(perms);
		this->_parent = parent;
		this->_priority = priority;
	}

	Access hasPermission(const plg::string& perm) const {
		auto ispl = std::views::split(perm, '.');
		uint64_t hashes[256];
		int i = 0;
		for (auto s: ispl) {
			hashes[i] = XXH3_64bits(s.data(), s.size());
			++i;
		}

		return _hasPermission(hashes, i);
	}

	Access _hasPermission(const uint64_t hashes[], const int sz) const {
		const Group* i = this;

		while (i) {
			Access temp = i->_nodes._hasPermission(hashes, sz);
			if (temp == Access::NotFound) i = i->_parent;
			else return temp;
		}
		return Access::NotFound;
	}
};