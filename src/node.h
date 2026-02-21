#pragma once
#include <queue>
#include <string_view>
#include <ranges>
#include <stack>

#include <parallel_hashmap/phmap.h>
#include <xxhash.h>
#include <plg/string.hpp>
#include <plg/vector.hpp>

#include "timer_system.h"

const uint64_t AllAccess = XXH3_64bits("*", 1);

extern void g_PermExpirationCallback([[maybe_unused]] uint32_t timer, const plg::vector<plg::any>& userData);

enum class Status : int32_t
{
    Success = 0,
    Allow = 1,
    Disallow = 2,
    PermNotFound = 3,
    CookieNotFound = 4,
    GroupNotFound = 5,
    ChildGroupNotFound = 6,
    ParentGroupNotFound = 7,
    ActorUserNotFound = 8,
    TargetUserNotFound = 9,
    GroupAlreadyExist = 10,
    UserAlreadyExist = 11,
    CallbackAlreadyExist = 12,
    CallbackNotFound = 13,
    PermAlreadyGranted = 14,
    TemporalGroup = 15,
    PermanentGroup = 16,
    GroupNotDefined = 17
};

struct string_hash
{
    using is_transparent = void; // Enables heterogeneous lookup

    auto operator()(const plg::string& txt) const
    {
        if constexpr (sizeof(void*) == 8)
            return XXH3_64bits(txt.data(), txt.size());
        else return XXH32(txt.data(), txt.size(), 0);
    }

    auto operator()(const std::string_view& txt) const
    {
        if constexpr (sizeof(void*) == 8)
            return XXH3_64bits(txt.data(), txt.size());
        else return XXH32(txt.data(), txt.size(), 0);
    }
};

PLUGIFY_FORCE_INLINE void parseTempString(const std::string_view& input, std::string_view& output, time_t& timestamp)
{
    int j = 0;
    auto spl = std::views::split(input, ' ');
    for (auto&& ss : spl)
    {
        if (j == 0)
            output = std::string_view(ss);
        else
        {
            std::from_chars(ss.begin(), ss.begin() + ss.size(), timestamp);
            break;
        }
        ++j;
    }
    assert (timestamp != 0);
}

struct Node
{
    phmap::flat_hash_map<plg::string, Node, string_hash> nodes; // nested nodes
    uint32_t timer; // timer id for temporal perms
    bool wildcard; // skip all nested nodes
    bool state; // indicates permission status (Allow/Disallow)
    bool end_node; // indicates non-intermediate node
    time_t timestamp;

    PLUGIFY_FORCE_INLINE Status _hasPermission(const std::string_view names[], const uint64_t hashes[],
                                               const int sz) const
    {
        const Node* current = this;
        const Node* lastWild = wildcard ? this : nullptr; // save last wildcard position

        for (int i = 0; i < sz; ++i)
        {
            auto it = current->nodes.find(names[i], hashes[i]);
            if (it == current->nodes.end())
            {
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

    PLUGIFY_FORCE_INLINE void deletePerm(std::string_view perm)
    {
        if (perm.starts_with('-'))
            perm = perm.substr(1);
        auto ispl = std::views::split(perm, '.');
        uint64_t hashes[64];
        std::string_view names[64];
        int i = 0;
        for (const auto&& s : ispl)
        {
            hashes[i] = XXH3_64bits(s.data(), s.size());
            names[i] = std::string_view(s);
            ++i;
            if (hashes[i - 1] == AllAccess)
                break;
        }
        this->deletePerm(names, hashes, i);
    }

    PLUGIFY_FORCE_INLINE void deletePerm(const std::string_view names[], const uint64_t hashes[], const int sz)
    {
        if (sz < 1) return;
        if (hashes[0] == AllAccess)
        {
            // Reset ROOT node to initial state
            this->nodes.clear();
            this->state = this->wildcard = false;
            return;
        }

        const bool hasWildcard = hashes[sz - 1] == AllAccess;

        Node* curNode = this;

        std::pair<Node*, int> ancestors[64];
        int count = 0;

        // find pre-last element
        for (int i = 0; i < sz - 1; ++i)
        {
            const auto it = curNode->nodes.find(names[i], hashes[i]);
            if (it == curNode->nodes.end()) return;

            // ancestors[count] = {parent_node, child_key};
            ancestors[count] = {curNode, i};
            ++count;
            curNode = &it->second;
        }

        if (hasWildcard)
        {
            for (auto& val : curNode->nodes | std::views::values)
                destroyAllTimers(val);
            curNode->nodes.clear();
        }
        // Not wildcard - clear only last
        else
        {
            const auto it = curNode->nodes.find(names[sz - 1], hashes[sz - 1]);
            if (it == curNode->nodes.end()) return;
            if (it->second.timer != 0xFFFFFFFF)
                g_TimerSystem.KillTimer(it->second.timer);
            for (auto& val : it->second.nodes | std::views::values)
                destroyAllTimers(val);
            curNode->nodes.erase(it);
        }

        if (curNode->end_node || !curNode->nodes.empty())
            return;

        // Delete empty nodes
        for (int i = (count - 1); i >= 0; --i)
        {
            Node* parent = ancestors[i].first;
            const auto it = parent->nodes.find(names[ancestors[i].second], hashes[ancestors[i].second]);
            if (it != parent->nodes.end())
                parent->nodes.erase(it);
            if (parent->end_node || !parent->nodes.empty()) // This node have state - stop
                return;
        }
    }

    PLUGIFY_FORCE_INLINE Node* addPerm(std::string_view perm)
    {
        const bool allow = !perm.starts_with('-');
        const bool hasWildcard = perm.ends_with('*');
        auto spl = std::views::split(perm, '.');

        Node* node = this;
        for (auto&& s : spl)
        {
            auto ss = std::string_view(s);
            if (ss.starts_with('-')) ss = ss.substr(1);
            if (ss == "*") break;
            node = &(node->nodes.try_emplace(plg::string(ss), phmap::flat_hash_map<plg::string, Node, string_hash>(),
                                             0xFFFFFFFF,
                                             false, false, false, 0).first->second);
        }
        node->state = allow;
        node->wildcard = hasWildcard;
        node->end_node = true;

        return node;
    }

    static void destroyAllTimers(Node& node)
    {
        if (node.timer != 0xFFFFFFFF)
            g_TimerSystem.KillTimer(node.timer);
        for (auto& val : node.nodes | std::views::values)
            destroyAllTimers(val);
    }

    PLUGIFY_FORCE_INLINE static void forceRehash(phmap::flat_hash_map<plg::string, Node, string_hash>& nodes)
    {
        // nodes.rehash(0);
        // for (std::pair<const plg::string, Node>& n : nodes) forceRehash(n.second.nodes);
        std::stack<phmap::flat_hash_map<plg::string, Node, string_hash>*> stack;
        stack.push(&nodes);
        while (!stack.empty())
        {
            auto* cur = stack.top();
            stack.pop();

            cur->rehash(0);

            for (auto& v : *cur | std::views::values)
                stack.push(&v.nodes);
        }
    }
};

inline void dumpNodes(const plg::string& base_name, const Node& root,
                      plg::vector<plg::string>& output_perms)
{
    if (root.end_node)
    {
        plg::string s = root.state ? "" : "-";
        s += base_name;
        if (root.wildcard)
            s += ".*";
        if (root.timestamp > 0)
            s += " " + plg::to_string(root.timestamp);
        output_perms.push_back(std::move(s));
    }
    for (const auto& [key, val] : root.nodes) dumpNodes(base_name + "." + key, val, output_perms);
}

PLUGIFY_FORCE_INLINE plg::vector<plg::string> dumpNode(const Node& root_node)
{
    plg::vector<plg::string> perms;
    if (root_node.wildcard)
        perms.push_back(
            (root_node.state ? "*" : "-*") + (
                root_node.timestamp > 0 ? (" " + plg::to_string(root_node.timestamp)) : ""));
    for (const auto& [key, val] : root_node.nodes) dumpNodes(key, val, perms);

    return perms;
}