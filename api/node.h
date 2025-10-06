#pragma once
#include <plugify/string.hpp>
#include <plugify/vector.hpp>
#include <string_view>

#include "xxhash.h"
#include "parallel_hashmap/phmap.h"

#include <ranges>
const uint64_t AllAccess = XXH3_64bits("*", 1);

enum class Access : int32_t {
	NotFound = 0,// Disallow
	Disallow = 1,
	Allow = 2
};

struct string_hash {
	using is_transparent = void;// Enables heterogeneous lookup

	auto operator()(const plg::string& txt) const {
		if constexpr (sizeof(void*) == 8) return XXH3_64bits(txt.data(), txt.size());
		else return XXH32(txt.data(), txt.size(), 0);
	}
};

struct Node {
	bool wildcard;// skip all nested nodes
	bool state;// indicates permission status (Allow/Disallow)
	plg::string name;// name of node
	phmap::flat_hash_map<uint64_t, Node> nodes;// nested nodes

	__always_inline Access _hasPermission(const uint64_t hashes[], const int sz) const {
		const Node* current = this;
		const Node* lastWild = wildcard ? this : nullptr;// save last wildcard position

		for (int i = 0; i < sz; ++i) {
			size_t hsh = hashes[i];
			auto it = current->nodes.find(hsh);
			if (it == current->nodes.end()) {
				// requested node not found - return wildcard status
				return lastWild ? (lastWild->state ? Access::Allow : Access::Disallow) : Access::NotFound;
			}

			// save current position
			current = &it->second;
			// save last wildcard position
			if (current->wildcard) lastWild = current;
		}

		return current->state ? Access::Allow : Access::Disallow;
	}

	__always_inline void deletePerm(const plg::string& perm) {
		auto ispl = std::views::split(perm, '.');
		uint64_t hashes[256];
		int i = 0;
		for (auto s: ispl) {
			hashes[i] = XXH3_64bits(s.data(), s.size());
			++i;
		}
		this->deletePerm(hashes, i);
	}

	__always_inline void deletePerm(const uint64_t hashes[], const int sz) {
		if (sz < 1) return;
		if (hashes[0] == AllAccess) this->nodes.clear();

		bool hasWildcard = hashes[sz - 1] == AllAccess;

		Node* t_node = this;

		// find pre-last element
		for (int i = 0; i < sz - 1; ++i) {
			const auto it = t_node->nodes.find(hashes[i]);
			if (it == t_node->nodes.end()) return;
			t_node = &it->second;
		}

		// clear all nested elements
		if (hasWildcard) t_node->nodes.clear();
		// clear this with nested elements
		else {
			const auto it = t_node->nodes.find(hashes[sz - 1]);
			if (it != t_node->nodes.end()) t_node->nodes.erase(it);
		}
	}

	__always_inline void addPerm(const plg::string& perm) {
		const bool allow = !perm.starts_with('-');
		const bool hasWildcard = perm.ends_with('*');
		auto spl = std::views::split(perm, '.');

		Node* node = this;
		for (auto s: spl) {
			auto ss = std::string_view(s);
			if (ss.starts_with('-')) ss = ss.substr(1);
			if (ss == "*") break;
			const uint64_t hash = XXH3_64bits(ss.data(), ss.size());
			node = &(node->nodes.try_emplace(hash, false, false, plg::string(ss), phmap::flat_hash_map<uint64_t, Node>()).first->second);
		}
		node->state = allow;
		node->wildcard = hasWildcard;
	}
};

inline void dumpNodes(const plg::string& base_name, const Node& n, plg::vector<plg::string>& perms) {
	if (n.wildcard) perms.push_back((n.state ? "" : "-") + base_name + "*");

	if (n.nodes.empty() && !n.wildcard) {
		// final path
		perms.push_back((n.state ? "" : "-") + base_name);
		return;
	}
	for (auto& kv: n.nodes) dumpNodes(base_name + kv.second.name + ".", kv.second, perms);
}

inline plg::vector<plg::string> dumpNode(const Node& root_node) {
	plg::vector<plg::string> perms;
	for (auto& kv: root_node.nodes) dumpNodes(kv.second.name, kv.second, perms);

	return perms;
}

inline void forceRehash(phmap::flat_hash_map<uint64_t, Node>& nodes) {
	nodes.rehash(0);
	for (std::pair<const uint64_t, Node>& n: nodes) forceRehash(n.second.nodes);
}

inline Node loadNode(const plg::vector<plg::string>& perms) {
	Node result{false, false, "ROOT", phmap::flat_hash_map<uint64_t, Node>()};
	for (const auto& perm: perms) {
		if (perm.empty())// empty lines?
			continue;
		if (perm.at(0) == '*') {
			// skip situation with perm "*"
			result.wildcard = true;
			continue;
		}

		auto spl = std::views::split(perm, '.');

		const bool state = !perm.starts_with('-');
		const bool wildcard = perm.ends_with('*');

		Node* node = &result;

		for (auto s: spl) {
			auto ss = std::string_view(s.begin(), s.end());
			if (ss.starts_with('-')) ss = ss.substr(1);
			if (ss == "*") break;
			const uint64_t hash = XXH3_64bits(ss.data(), ss.size());
			node = &(node->nodes.try_emplace(hash, false, false, plg::string(ss), phmap::flat_hash_map<uint64_t, Node>()).first->second);
		}

		node->state = state;
		node->wildcard = wildcard;
	}
	forceRehash(result.nodes);// to speedup lookup
	return result;
}