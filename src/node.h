#pragma once
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
                                               const int sz, const bool exact, bool& w_wildcard, time_t& w_timestamp) const
    {
        w_wildcard = false;
        const bool l_wildcard = hashes[sz - 1] == AllAccess;
        const int counter = l_wildcard ? sz - 1 : sz;
        if (sz == 1 && l_wildcard)
        {
            if (this->wildcard)
                return this->state ? Status::Allow : Status::Disallow;
            return Status::PermNotFound;
        }
        const Node* current = this;
        const Node* lastWild = wildcard ? this : nullptr; // save last wildcard position

        for (int i = 0; i < counter; ++i)
        {
            auto it = current->nodes.find(names[i], hashes[i]);
            if (it == current->nodes.end())
            {
                if (exact)
                    return Status::PermNotFound;
                // requested node not found - return wildcard status
                return lastWild ? (lastWild->state ? Status::Allow : Status::Disallow) : Status::PermNotFound;
            }

            // save current position
            current = &it->second;
            // save last wildcard position
            if (current->wildcard) lastWild = current;
        }

        // Check non-intermediate node
        if (current->end_node)
        {
            if (exact)
                w_wildcard = current->wildcard;
            w_timestamp = current->timestamp;
            return current->state ? Status::Allow : Status::Disallow;
        }
        if (exact)
            return Status::PermNotFound;
        if (lastWild)
        {
            w_timestamp = lastWild->timestamp;
            return lastWild->state ? Status::Allow : Status::Disallow;
        }
        return Status::PermNotFound;
    }

    PLUGIFY_FORCE_INLINE bool deletePerm(std::string_view perm, const bool recursive_delete,
                                         plg::vector<plg::string>& deleted_perms)
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
        // deleted_perms.clear();
        return this->deletePerm(names, hashes, i, recursive_delete, deleted_perms);
    }

    PLUGIFY_FORCE_INLINE bool deletePerm(const std::string_view names[], const uint64_t hashes[], const int sz,
                                         const bool recursive_delete, plg::vector<plg::string>& deleted_perms)
    {
        if (sz < 1) return false;

        const bool hasWildcard = hashes[sz - 1] == AllAccess;
        const int counter = sz - 1;
        // int count = 0;
        Node* curNode = this;
        // std::pair<Node*, int> ancestors[64];

        if (hashes[0] == AllAccess)
        {
            if (!curNode->wildcard)
                return false;

            if (curNode->timestamp != 0)
            {
                g_TimerSystem.KillTimer(curNode->timer);
                // Timer has been defused!
                curNode->timer = 0xFFFFFFFF;
            }

            if (recursive_delete)
            {
                deleted_perms = dumpNode(*curNode, false);
                destroyAllTimers(*curNode);
                curNode->nodes.clear();
            }
            else
                deleted_perms.push_back(curNode->state ? "*" : "-*");
            curNode->timestamp = 0;
            curNode->end_node = curNode->state = curNode->wildcard = false;
            return true;
        }

        // find pre-last element
        for (int i = 0; i < counter; ++i)
        {
            const auto it = curNode->nodes.find(names[i], hashes[i]);
            if (it == curNode->nodes.end()) return false;

            // ancestors[count] = {curNode, count};
            // ++count;
            curNode = &it->second;
        }

        Node* nodeReset = curNode;

        if (!hasWildcard)
        {
            const auto it = curNode->nodes.find(names[counter], hashes[counter]);
            if (it == curNode->nodes.end()) return false; // Node not found
            nodeReset = &it->second;
        }

        plg::string base_name = names[0];
        {
            for (int i = 1; i < counter; ++i)
            {
                base_name += '.';
                base_name += names[i];
            }
            if (!hasWildcard)
            {
                base_name += '.';
                base_name += names[counter];
            }
        }
        if (recursive_delete)
        {
            dumpNodes(base_name, *nodeReset, deleted_perms);
            destroyAllTimers(*nodeReset);
            nodeReset->nodes.clear();
        }
        else
        {
            if (!nodeReset->state)
                base_name.insert(0, "-");

            deleted_perms.push_back(base_name);
        }

        if (nodeReset->timestamp != 0)
        {
            g_TimerSystem.KillTimer(nodeReset->timer);
            nodeReset->timer = 0xFFFFFFFF;
        }
        nodeReset->timestamp = 0;
        nodeReset->state = nodeReset->wildcard = nodeReset->end_node = false;

        return true;

        // TODO: Rework cleaning of empty nodes
        // // Skip non-empty nodes
        // if (!nodeReset->nodes.empty())
        //     return true;
        //
        // // Delete empty nodes
        // for (int i = (count - 1); i >= 0; --i)
        // {
        //     Node* parent = ancestors[i].first;
        //     const auto it = parent->nodes.find(names[ancestors[i].second], hashes[ancestors[i].second]);
        //     if (it != parent->nodes.end())
        //         parent->nodes.erase(it);
        //     if (parent->end_node || !parent->nodes.empty()) // This node have state - stop
        //         break;
        // }
        // return true;
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
        {
            g_TimerSystem.KillTimer(node.timer);
            node.timer = 0xFFFFFFFF;
        }
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

    inline static void dumpNodes(const plg::string& base_name, const Node& root,
                                 plg::vector<plg::string>& output_perms, const bool preserve_state = true)
    {
        if (root.end_node)
        {
            plg::string s;
        	if (preserve_state && !root.state)
        		s += "-";
            s += base_name;
            if (root.wildcard)
                s += ".*";
            if (root.timestamp > 0)
                s += " " + plg::to_string(root.timestamp);
            output_perms.push_back(std::move(s));
        }
        for (const auto& [key, val] : root.nodes) dumpNodes(base_name + "." + key, val, output_perms);
    }

    PLUGIFY_FORCE_INLINE static plg::vector<plg::string> dumpNode(const Node& root_node, const bool preserve_state = true)
    {
        plg::vector<plg::string> perms;
        if (root_node.wildcard) {
        	plg::string s = root_node.state ? "*" : (preserve_state ? "-*" : "*");
        	if (root_node.timestamp > 0)
        		s += " " + plg::to_string(root_node.timestamp);
	        perms.push_back(s);
        }
        for (const auto& [key, val] : root_node.nodes) dumpNodes(key, val, perms, preserve_state);

        return perms;
    }
};
