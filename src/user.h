#pragma once
#include "group.h"

#include <parallel_hashmap/phmap.h>
#include <plg/any.hpp>
#include <plg/string.hpp>
#include <plg/vector.hpp>

#include "group_manager.h"
#include "timer_system.h"

struct User;

struct TempGroup
{
    time_t timestamp;
    Group* group;
    uint32_t timer;
};

inline bool sortF(const Group* i, const Group* j) { return i->_priority > j->_priority; }

inline bool sortFF(const TempGroup& i, const TempGroup& j)
{
    return i.group->_priority > j.group->_priority;
}

void g_PermExpirationCallback(uint32_t, const plg::vector<plg::any>&);
void g_GroupExpirationCallback(uint32_t, const plg::vector<plg::any>&);

extern Group* GetGroup(const std::string_view& name);

struct User
{
    Node user_nodes; // nodes of user
    // 1. Load from groups settings
    // 2. Load from players settings
    Node temp_nodes;

    phmap::flat_hash_map<plg::string, plg::any, string_hash, std::equal_to<>> cookies;
    plg::vector<Group*> _groups; // groups that player belongs to
    plg::vector<TempGroup> _t_groups; // temporal groups
    int _immunity;

    [[nodiscard]] int getImmunity() const
    {
        if (_immunity == -1) // Force use group's priority
            return std::max(_groups.empty() ? -1 : _groups.front()->_priority,
                            _t_groups.empty() ? -1 : _t_groups.front().group->_priority);
        return _immunity;
    }

    [[nodiscard]] Status hasPermission(std::string_view perm, uint16_t& perm_type) const
    {
        if (perm.starts_with('-'))
            perm = perm.substr(1);
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
        if (hasPerm != Status::PermNotFound) // Check if user defined this permission temporarily
        {
            perm_type = 0;
            return hasPerm;
        }

        hasPerm = user_nodes._hasPermission(names, hashes, i);
        if (hasPerm != Status::PermNotFound) // Check if user defined this permission
        {
            perm_type = 1;
            return hasPerm;
        }

        for (const auto& p : _t_groups)
        {
            hasPerm = p.group->_hasPermission(names, hashes, i);
            if (hasPerm != Status::PermNotFound)
            {
                perm_type = 2;
                return hasPerm;
            }
        }

        for (const auto g : _groups)
        {
            hasPerm = g->_hasPermission(names, hashes, i);
            if (hasPerm != Status::PermNotFound)
            {
                perm_type = 3;
                return hasPerm;
            }
        }
        perm_type = 4;
        return Status::PermNotFound;
    }

    PLUGIFY_FORCE_INLINE bool addPerm(const plg::string& perm, time_t timestamp, uint64_t user_id)
    {
        uint16_t perm_type;
        const bool denied = perm.starts_with('-');
        const Status status = hasPermission(perm, perm_type);
        const bool diff = !((denied && status == Status::Disallow) || (!denied && status == Status::Allow));

        if (timestamp != 0) // Add temp permission
        {
            // Temporal or defined in groups (or not defined at all)
            if (perm_type != 1)
            {
                if (!diff)
                    return false;
                addTempPerm(perm, timestamp, user_id);
            }
            // perm_type == 1 (permanent permission)
            else if (!diff)
                return false;
            else // Differs from permanent perm by allowance
                addTempPerm(perm, timestamp, user_id);
        }
        else // Add permanent permission
        {
            if (perm_type == 0) // Delete temporal permission anyway
                temp_nodes.deletePerm(perm);
            else if (!diff && perm_type != 2) // No difference with group
                return false;
            user_nodes.addPerm(perm);
        }

        return true;
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
        this->_t_groups.emplace_back(timestamp, g, timer);
        this->sortGroups();
    }

    PLUGIFY_FORCE_INLINE bool delTempGroup(const Group* g)
    {
        for (auto it = this->_t_groups.begin(); it != this->_t_groups.end(); ++it)
        {
            if (g == it->group)
            {
                g_TimerSystem.KillTimer(it->timer);
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

    User(int immunity, plg::vector<Group*>&& __groups, const plg::vector<plg::string>& perms,
         const plg::vector<plg::string>& temp_perms, const plg::vector<plg::string>& temp_groups,
         const uint64_t user_id)
    {
        this->_immunity = immunity;
        this->_groups = std::move(__groups);
        for (const plg::string& s : temp_groups)
        {
            std::string_view group_view;
            time_t timestamp = 0;
            parseTempString(s, group_view, timestamp);
            Group* g = GetGroup(group_view);
            // Skip missed or already defined groups
            if (g == nullptr)
                continue;

            bool found = false;
            for (const auto gg : this->_groups)
            {
                const Group* ggg = gg;
                while (ggg)
                {
                    if (ggg == g)
                    {
                        found = true;
                        break;
                    }
                    ggg = ggg->_parent;
                }
            }
            if (!found)
                addTempGroup(g, timestamp, user_id);
        }
        sortGroups();
        // this->user_nodes = Node::loadNode(perms);
        // this->temp_nodes = Node::loadTempNode(temp_perms, user_id);
        // Remark: this change was made to resolve inconsistency with collisions in groups/permanent/temporal permissions
        this->user_nodes = {phmap::flat_hash_map<plg::string, Node, string_hash>(), 0xFFFFFFFF, false, false, true, 0};
        this->temp_nodes = {phmap::flat_hash_map<plg::string, Node, string_hash>(), 0xFFFFFFFF, false, false, true, 0};
        for (const plg::string& s : perms)
            addPerm(s, 0, user_id);

        for (const plg::string& s : temp_perms)
        {
            std::string_view perm_view;
            time_t timestamp = 0;
            parseTempString(s, perm_view, timestamp);
            addPerm(plg::string(perm_view), timestamp, user_id);
        }

        Node::forceRehash(this->user_nodes.nodes);
        Node::forceRehash(this->temp_nodes.nodes);
    }
};
