#pragma once
#include <string_view>
#include <ranges>

#include <parallel_hashmap/phmap.h>
#include <xxhash.h>
#include <plg/string.hpp>
#include <plg/vector.hpp>

const uint64_t AllAccess = XXH3_64bits("*", 1);

enum class Status : int32_t {
	Success = 0,
	Allow = Success,
	Disallow = 1,
	GroupNotFound = 2,
	ChildGroupNotFound = GroupNotFound,
	ParentGroupNotFound = 3,
	ActorUserNotFound = 4,
	TargetUserNotFound = 5,
	PermNotFound = 6,
	CookieNotFound = PermNotFound,
	GroupAlreadyExist = 7,
	UserAlreadyExist = GroupAlreadyExist,

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

	__always_inline Status _hasPermission(const uint64_t hashes[], const int sz) const {
		const Node* current = this;
		const Node* lastWild = wildcard ? this : nullptr;// save last wildcard position

		for (int i = 0; i < sz; ++i) {
			size_t hsh = hashes[i];
			auto it = current->nodes.find(hsh);
			if (it == current->nodes.end()) {
				// requested node not found - return wildcard status
				return lastWild ? (lastWild->state ? Status::Allow : Status::Disallow) : Status::PermNotFound;
			}

			// save current position
			current = &it->second;
			// save last wildcard position
			if (current->wildcard) lastWild = current;
		}

		return current->state ? Status::Allow : Status::Disallow;
	}

	PLUGIFY_FORCE_INLINE void deletePerm(const plg::string& perm) {
		auto ispl = std::views::split(perm, '.');
		uint64_t hashes[256];
		int i = 0;
		for (auto&& s: ispl) {
			hashes[i] = XXH3_64bits(s.data(), s.size());
			++i;
			if (hashes[i - 1] == AllAccess)
				break;
		}
		this->deletePerm(hashes, i);
	}

	PLUGIFY_FORCE_INLINE void deletePerm(const uint64_t hashes[], const int sz) {
		if (sz < 1) return;
		if (hashes[0] == AllAccess) {
			this->nodes.clear();
			return;
		}

		bool hasWildcard = hashes[sz - 1] == AllAccess;

		Node* curNode = this;

		std::pair<Node*, uint64_t> ancestors[256];
		int count = 0;

		// find pre-last element
		for (int i = 0; i < sz - 1; ++i) {
			const auto it = curNode->nodes.find(hashes[i]);
			if (it == curNode->nodes.end()) return;

			// ancestors[count] = {parent_node, child_key};
			ancestors[count] = {curNode, hashes[i]};
			++count;
			curNode = &it->second;
		}

		if (hasWildcard) {
			curNode->nodes.clear();
			// Do not delete 'root' node
			return;
		}
		// Not wildcard - clear only last
		const auto it = curNode->nodes.find(hashes[sz - 1]);
		if (it == curNode->nodes.end()) return;
		curNode->nodes.erase(it);

		if (curNode->wildcard || !curNode->nodes.empty())
			return;

		// Delete empty node
		for (int i = (count - 1); i >= 0; --i) {
			Node* parent = ancestors[i].first;
			const uint64_t key = ancestors[i].second;
			parent->nodes.erase(key);
			if (curNode->wildcard || !curNode->nodes.empty())
				return;
		}
	}

	PLUGIFY_FORCE_INLINE void addPerm(const plg::string& perm) {
		const bool allow = !perm.starts_with('-');
		const bool hasWildcard = perm.ends_with('*');
		auto spl = std::views::split(perm, '.');

		Node* node = this;
		for (auto&& s: spl) {
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
	for (auto& kv: n.nodes) dumpNodes(base_name + "." + kv.second.name, kv.second, perms);
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
	for (const plg::string& perm: perms) {
		if (perm.empty())// empty lines?
			continue;
		if (perm.at(0) == '*') {
			// skip situation with perm "*"
			result.wildcard = true;
			continue;
		}

		auto spl = std::views::split(perm, '.');

		const bool state = !perm.starts_with('-');
		bool wildcard = false;

		Node* node = &result;

		for (auto&& s: spl) {
			auto ss = std::string_view(s.begin(), s.end());
			if (ss.starts_with('-')) ss = ss.substr(1);
			if (ss == "*") {
				wildcard = true;
				break;
			};
			const uint64_t hash = XXH3_64bits(ss.data(), ss.size());
			node = &(node->nodes.try_emplace(hash, false, false, plg::string(ss), phmap::flat_hash_map<uint64_t, Node>()).first->second);
		}

		node->state = state;
		node->wildcard = wildcard;
	}
	forceRehash(result.nodes);// to speedup lookup
	return result;
}