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

inline bool sortFF(const TempGroup& i, const TempGroup& j)
{
    return i.group->_priority > j.group->_priority;
}

enum class PermSource : uint32_t
{
    UserTemp = 0,
    User = 1,
    GroupTemp = 2,
    Group = 3,
    NotFound = 4,
};

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
    plg::vector<TempGroup> _groups; // groups that player belongs to
    int _immunity;

    [[nodiscard]] PLUGIFY_FORCE_INLINE int getImmunity() const
    {
        if (_immunity == -1)
            return _groups.empty() ? -1 : _groups.front().group->_priority;
        return _immunity;
    }

    [[nodiscard]] Status hasPermission(std::string_view perm, PermSource& perm_type, const bool exact, bool& w_wildcard, time_t& w_timestamp) const
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
            if (hashes[i - 1] == AllAccess)
                break;
        }

        Status hasPerm = temp_nodes._hasPermission(names, hashes, i, exact, w_wildcard, w_timestamp);
        if (hasPerm != Status::PermNotFound) // Check if user defined this permission temporarily
        {
            perm_type = PermSource::UserTemp;
            return hasPerm;
        }

        hasPerm = user_nodes._hasPermission(names, hashes, i, exact, w_wildcard, w_timestamp);
        if (hasPerm != Status::PermNotFound) // Check if user defined this permission
        {
            perm_type = PermSource::User;
            return hasPerm;
        }

        for (const auto g : _groups)
        {
            hasPerm = g.group->_hasPermission(names, hashes, i, exact, w_wildcard);
            if (hasPerm != Status::PermNotFound)
            {
                perm_type = g.timestamp == 0 ? PermSource::Group : PermSource::GroupTemp;
                return hasPerm;
            }
        }
        perm_type = PermSource::NotFound;
        return Status::PermNotFound;
    }

    PLUGIFY_FORCE_INLINE void addTempPerm(const std::string_view& perm, time_t timestamp, uint64_t user_id)
    {
        Node* node = temp_nodes.addPerm(perm);
        if (node->timer == 0xFFFFFFFF)
            node->timer = g_TimerSystem.CreateTimer(static_cast<double>(timestamp) - static_cast<double>(time(nullptr)),
                                                    g_PermExpirationCallback, TimerFlag::Default,
                                                    plg::vector<plg::any>{
                                                        perm,
                                                        node->state,
                                                        user_id
                                                    });
        else
            g_TimerSystem.RescheduleTimer(node->timer,
                                          static_cast<double>(timestamp) - static_cast<double>(time(nullptr)));
        node->timestamp = timestamp;
    }

    PLUGIFY_FORCE_INLINE void addGroup(Group* g, time_t timestamp, uint64_t targetID)
    {
        TempGroup& tg = this->_groups.emplace_back(timestamp, g, 0xFFFFFFFF);
        if (timestamp != 0)
        {
            tg.timer = g_TimerSystem.CreateTimer(static_cast<double>(timestamp) - static_cast<double>(time(nullptr)),
                                                 g_GroupExpirationCallback, TimerFlag::Default, plg::vector<plg::any>{
                                                     g->_name,
                                                     targetID
                                                 });
        }
        this->sortGroups();
    }

    PLUGIFY_FORCE_INLINE bool delGroup(const Group* g)
    {
        for (auto it = this->_groups.begin(); it != this->_groups.end(); ++it)
        {
            if (g == it->group)
            {
                if (it->timestamp != 0)
                    g_TimerSystem.KillTimer(it->timer);
                this->_groups.erase(it);
                return true;
            }
        }
        return false;
    }

    PLUGIFY_FORCE_INLINE void sortGroups()
    {
        std::ranges::sort(this->_groups, sortFF);
    }

    User(const int immunity, const plg::vector<plg::string>& groupsList, const plg::vector<plg::string>& permsList,
         const uint64_t user_id)
    {
        this->_immunity = immunity;
        for (const plg::string& s : groupsList)
        {
            std::string_view group_view;
            time_t timestamp = 0;
            parseTempString(s, group_view, timestamp);
            Group* g = GetGroup(group_view);
            // Skip missed or already defined groups
            if (g == nullptr || timestamp != 0)
                continue;

            bool found = false;
            for (const auto gg : this->_groups)
            {
                const Group* ggg = gg.group;
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
                addGroup(g, 0, user_id);
        }
        for (const plg::string& s : groupsList)
        {
            std::string_view group_view;
            time_t timestamp = 0;
            parseTempString(s, group_view, timestamp);
            Group* g = GetGroup(group_view);
            // Skip missed or already defined groups
            if (g == nullptr || timestamp == 0)
                continue;

            bool found = false;
            for (const auto gg : this->_groups)
            {
                const Group* ggg = gg.group;
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
                addGroup(g, timestamp, user_id);
        }
        sortGroups();
        this->user_nodes = {phmap::flat_hash_map<plg::string, Node, string_hash>(), 0xFFFFFFFF, false, false, true, 0};
        this->temp_nodes = {phmap::flat_hash_map<plg::string, Node, string_hash>(), 0xFFFFFFFF, false, false, true, 0};

        for (const plg::string& s : permsList)
        {
            std::string_view perm_view;
            time_t timestamp = 0;
            parseTempString(s, perm_view, timestamp);
            if (timestamp != 0)
                continue;
            this->user_nodes.addPerm(perm_view);
        }
        for (const plg::string& s : permsList)
        {
            std::string_view perm_view;
            time_t timestamp = 0;
            parseTempString(s, perm_view, timestamp);
            if (timestamp == 0)
                continue;
            this->addTempPerm(perm_view, timestamp, user_id);
        }


        Node::forceRehash(this->user_nodes.nodes);
        Node::forceRehash(this->temp_nodes.nodes);
    }
};
