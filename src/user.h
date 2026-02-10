#pragma once
#include "group.h"

#include <parallel_hashmap/phmap.h>
#include <plg/any.hpp>
#include <plg/string.hpp>
#include <plg/vector.hpp>

#include "group_manager.h"
#include "timer_system.h"

struct User;
inline bool sortF(const Group* i, const Group* j) { return i->_priority > j->_priority; }

inline bool sortFF(const std::pair<uint32_t, Group*> i, const std::pair<uint32_t, Group*> j)
{
    return i.second->_priority > j.second->_priority;
}

void g_PermExpirationCallback(uint32_t, const plg::vector<plg::any>&);
void g_GroupExpirationCallback(uint32_t, const plg::vector<plg::any>&);

extern Group* GetGroup(const plg::string& name);

struct User
{
    Node user_nodes; // nodes of user
    // 1. Load from groups settings
    // 2. Load from players settings
    Node temp_nodes;

    phmap::flat_hash_map<plg::string, plg::any, string_hash, std::equal_to<>> cookies;
    plg::vector<Group*> _groups; // groups that player belongs to
    plg::vector<std::pair<uint32_t, Group*>> _t_groups; // temporal groups
    int _immunity;

    bool hasGroup(const plg::string& s)
    {
        for (const auto& g : _groups)
        {
            const Group* i = g;
            while (i)
            {
                if (s == i->_name) return true;
                i = i->_parent;
            }
        }
        return false;
    }

    [[nodiscard]] Status hasPermission(const plg::string& perm) const
    {
        auto ispl = std::views::split(perm, '.');
        uint64_t hashes[64];
        std::string_view names[64];
        int i = 0;
        for (auto&& s : ispl)
        {
            // hashes[i] = calcHash(s);
            hashes[i] = XXH3_64bits(s.data(), s.size());
            names[i] = std::string_view(s);
            ++i;
        }

        Status hasPerm = temp_nodes._hasPermission(names, hashes, i);
        if (hasPerm != Status::PermNotFound) // Check if user defined this permission
            return hasPerm;

        hasPerm = user_nodes._hasPermission(names, hashes, i);
        if (hasPerm != Status::PermNotFound) // Check if user defined this permission
            return hasPerm;

        for (const auto& p : _t_groups)
        {
            hasPerm = p.second->_hasPermission(names, hashes, i);
            if (hasPerm != Status::PermNotFound) return hasPerm;
        }

        for (const auto g : _groups)
        {
            hasPerm = g->_hasPermission(names, hashes, i);
            if (hasPerm != Status::PermNotFound) return hasPerm;
        }
        return Status::PermNotFound;
    }

    PLUGIFY_FORCE_INLINE void addTempPerm(const plg::string& perm, time_t timestamp, uint64_t user_id)
    {
        Node* node = temp_nodes.addPerm(perm);
        if (node->timer == 0xFFFFFFFF)
            node->timer = g_TimerSystem.CreateTimer(static_cast<double>(timestamp) - static_cast<double>(time(nullptr)),
                                                    g_PermExpirationCallback, TimerFlag::Default,
                                                    plg::vector<plg::any>{
                                                        perm,
                                                        user_id
                                                    });
        else
            g_TimerSystem.RescheduleTimer(node->timer,
                                          static_cast<double>(timestamp) - static_cast<double>(time(nullptr)));
        node->timestamp = timestamp;
    }

    PLUGIFY_FORCE_INLINE void addTempGroup(Group* g, time_t timestamp, uint64_t targetID)
    {
        uint32_t timer = g_TimerSystem.CreateTimer(static_cast<double>(timestamp) - static_cast<double>(time(nullptr)),
                                                   g_GroupExpirationCallback, TimerFlag::Default, plg::vector<plg::any>{
                                                       g->_name,
                                                       targetID
                                                   });
        this->_t_groups.emplace_back(timer, g);
        this->sortGroups();
    }

    PLUGIFY_FORCE_INLINE bool delTempGroup(Group* g)
    {
        for (auto it = this->_t_groups.begin(); it != this->_t_groups.end(); ++it)
        {
            if (g == it->second)
            {
                g_TimerSystem.KillTimer(it->first);
                this->_t_groups.erase(it);
                return true;
            }
        }
        return false;
    }

    PLUGIFY_FORCE_INLINE void sortGroups()
    {
        std::ranges::sort(this->_groups, sortF);
        std::ranges::sort(this->_t_groups, sortFF);
    }

    User(int immunity, plg::vector<Group*>&& __groups, const plg::vector<plg::string>& perms)
    {
        this->_immunity = immunity;
        this->_groups = std::move(__groups);
        sortGroups();
        this->user_nodes = Node::loadNode(perms);
        this->temp_nodes = {phmap::flat_hash_map<plg::string, Node>(), 0xFFFFFFFF, false, false, false, 0};
    }
};
