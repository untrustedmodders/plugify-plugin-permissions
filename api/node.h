#pragma once
#include <plugify/string.hpp>
#include <plugify/vector.hpp>
#include <string_view>
#include <unordered_map>

#include "xxhash.h"

#include <ranges>
const uint64_t AllAccess = XXH3_64bits("*", 1);

enum class Access : int32_t {
	NotFound = 0,// Disallow
	Disallow = 1,
	Allow = 2
};

struct Node {
	bool wildcard;// skip all nested nodes
	bool state;// indicates permission status (Allow/Disallow)
	plg::string name;// name of node
	std::unordered_map<uint64_t, Node> nodes;// nested nodes

	__always_inline Access _hasPermission(const uint64_t hashes[], const int sz) const {
		bool found = true;
		const Node* start = this;
		const Node* lwildcard = wildcard ? this : nullptr;// save last wildcard position

		for (int i = 0; i < sz; ++i) {
			size_t hsh = hashes[i];
			auto it = nodes.find(hsh);
			if (it == nodes.end()) {
				// requested node not found - return wildcard status
				found = false;
				break;
			}

			start = &it->second;
			if (start->wildcard) {
				// skip nested nodes - return state of root?
				if (start->nodes.empty())// empty wildcard - just return state of it
					return start->state ? Access::Allow : Access::Disallow;
				// no - save last position
				lwildcard = start;
			}
		}

		if (found)// return direct/overriden permission
			return start->state ? Access::Allow : Access::Disallow;
		if (lwildcard)// found last wildcard position
			return lwildcard->state ? Access::Allow : Access::Disallow;
		return Access::NotFound;
	}

	__always_inline void deletePerm(const plg::string& perm) {
		auto ispl = std::views::split(perm, '.');
		uint64_t hashes[256];
		int i = 0;
		for (auto s: ispl) {
			// hashes[i] = calcHash(s);
			hashes[i] = XXH3_64bits(s.data(), s.size());
			++i;
		}
		this->deletePerm(hashes, i);
	}

	__always_inline void deletePerm(const uint64_t hashes[], const int sz) {
		if (sz < 1) return;
		if (hashes[0] == AllAccess) this->nodes.clear();

		bool lwildcard = hashes[sz - 1] == AllAccess;

		Node* t_node = this;
		for (int i = 0; i < sz; ++i) {
			if (t_node->nodes.contains(hashes[i])) t_node = &t_node->nodes.at(hashes[i]);
			else return;
		}
		if (!lwildcard) {
			auto it = t_node->nodes.find(hashes[sz - 1]);
			if (it != t_node->nodes.end()) t_node->nodes.erase(it);
		} else t_node->nodes.clear();
	}

	__always_inline void addPerm(const plg::string& perm) {
		bool lstate = !perm.starts_with('-');
		bool lwildcard = perm.ends_with('*');
		auto spl = std::views::split(perm, '.');

		Node* node = this;
		for (auto s: spl) {
			auto ss = std::string_view(s);
			if (ss.starts_with('-')) ss = ss.substr(1);
			if (ss == "*") continue;
			if (uint64_t hash = XXH3_64bits(ss.data(), ss.size()); this->nodes.contains(hash)) node = &this->nodes.at(hash);
			else node = &(node->nodes.at(hash) = Node(false, false, plg::string(ss), std::unordered_map<uint64_t, Node>()));
		}
		node->state = lstate;
		node->wildcard = lwildcard;
	}
};

inline void dumpNodes(const plg::string& base_name, const Node& n, plg::vector<plg::string>& perms) {
	if (n.wildcard) perms.push_back((n.state ? "-" : "") + base_name + "*");

	if (n.nodes.empty() && !n.wildcard) {
		// final path
		perms.push_back((n.state ? "-" : "") + base_name);
		return;
	}
	for (auto& kv: n.nodes) dumpNodes(base_name + kv.second.name + ".", kv.second, perms);
}

inline plg::vector<plg::string> dumpNode(const Node& root_node) {
	plg::vector<plg::string> perms;
	for (auto& kv: root_node.nodes) dumpNodes(kv.second.name, kv.second, perms);

	return perms;
}

inline void forceRehash(std::unordered_map<uint64_t, Node>& nodes) {
	nodes.rehash(0);
	for (std::pair<const uint64_t, Node>& n: nodes) forceRehash(n.second.nodes);
}

inline Node loadNode(const plg::vector<plg::string>& perms) {
	Node result;
	result.name = "ROOT";
	for (const auto& perm: perms) {
		const plg::string* iperm = &perm;
		if (iperm->empty())// empty lines?
			continue;
		if (iperm->at(0) == '*') {
			// skip situation with perm "*"
			result.wildcard = true;
			continue;
		}

		auto spl = std::views::split(*iperm, '.');

		const bool state = !iperm->starts_with('-');
		const bool wildcard = iperm->ends_with('*');

		Node* node = &result;

		for (auto s: spl) {
			auto ss = std::string_view(s.begin(), s.end());
			if (ss.starts_with('-')) ss = ss.substr(1);
			if (ss == "*") break;
			if (uint64_t hash = XXH3_64bits(ss.data(), ss.size()); node->nodes.contains(hash)) node = &node->nodes.at(hash);
			else { node = &(node->nodes[hash] = Node(false, false, plg::string(ss), std::unordered_map<uint64_t, Node>())); }
		}

		node->state = state;
		node->wildcard = wildcard;
	}
	forceRehash(result.nodes);// to speedup lookup
	return result;
}