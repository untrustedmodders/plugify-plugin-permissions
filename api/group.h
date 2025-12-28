#pragma once
#include "node.h"
#include <plg/vector.hpp>
#include <plg/string.hpp>

#include "xxhash.h"
#include "parallel_hashmap/phmap.h"
#include <plg/any.hpp>

struct Group {
	Group* _parent;// root of this group
	plg::string _name;// name of group
	int _priority;// priority of group
	phmap::flat_hash_map<plg::string, plg::any, string_hash, std::equal_to<>> cookies;// group cookies
	Node _nodes;// nodes of group

	Group(const plg::vector<plg::string>& perms, const plg::string& name, const int priority, Group* parent = nullptr) {
		this->_name = name;
		this->_nodes = loadNode(perms);
		this->_parent = parent;
		this->_priority = priority;
	}

	[[nodiscard]] Status hasPermission(const plg::string& perm) const {
		std::string_view sv(perm);
		auto ispl = std::views::split(sv, '.');
		uint64_t hashes[256];
		int i = 0;
		for (auto&& s: ispl) {
			const auto ptr = s.empty() ? nullptr : &*s.begin();
			const auto len = s.size();
			hashes[i] = XXH3_64bits(ptr, len);
			++i;
		}

		return _hasPermission(hashes, i);
	}

	Status _hasPermission(const uint64_t hashes[], const int sz) const {
		const Group* i = this;

		while (i) {
			Status temp = i->_nodes._hasPermission(hashes, sz);
			if (temp == Status::PERM_NOT_FOUND) i = i->_parent;
			else return temp;
		}
		return Status::PERM_NOT_FOUND;
	}
};