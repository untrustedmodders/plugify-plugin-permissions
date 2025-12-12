#pragma once
#include "group.h"
#include "parallel_hashmap/phmap.h"

#include <plg/any.hpp>
#include <plg/string.hpp>
#include <plg/vector.hpp>

inline bool sortF(const Group* i, const Group* j) { return i->_priority > j->_priority; }

struct User {
	Node nodes;// nodes of user
	// 1. Load from groups settings
	// 2. Load from players settings

	phmap::flat_hash_map<plg::string, plg::any, string_hash, std::equal_to<>> cookies;
	plg::vector<Group*> _groups;// groups that player belongs to
	int _immunity;

	bool hasGroup(const plg::string& s) {
		for (const auto& g: _groups) {
			const Group* i = g;
			while (i) {
				if (s == i->_name) return true;
				i = i->_parent;
			}
		}
		return false;
	}

	Access hasPermission(const plg::string& perm) const {
		auto ispl = std::views::split(perm, '.');
		uint64_t hashes[256];
		int i = 0;
		for (auto&& s: ispl) {
			// hashes[i] = calcHash(s);
			hashes[i] = XXH3_64bits(s.data(), s.size());
			++i;
		}
		Access hasPerm = nodes._hasPermission(hashes, i);
		if (hasPerm != Access::NotFound)// Check if user defined this permission
			return hasPerm;

		for (const auto g: _groups) {
			hasPerm = g->_hasPermission(hashes, i);
			if (hasPerm != Access::NotFound) return hasPerm;
		}
		return Access::NotFound;
	}

	void sortGroups() { std::sort(this->_groups.begin(), this->_groups.end(), sortF); }

	User(int immunity, plg::vector<Group*>&& _groups, const plg::vector<plg::string>& perms) {
		this->_immunity = immunity;
		this->_groups = std::move(_groups);
		sortGroups();
		this->nodes = loadNode(perms);
	}
};