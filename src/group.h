#pragma once
#include "node.h"

#include <xxhash.h>
#include <parallel_hashmap/phmap.h>
#include <plg/any.hpp>
#include <plg/string.hpp>
#include <plg/vector.hpp>

struct Group
{
    Group* _parent; // root of this group
    plg::string _name; // name of group
    int _priority; // priority of group
    phmap::flat_hash_map<plg::string, plg::any, string_hash, std::equal_to<>> cookies; // group cookies
    Node _nodes; // nodes of group

    Group(const plg::vector<plg::string>& perms, const plg::string& name, const int priority, Group* parent = nullptr)
    {
        this->_name = name;
        this->_parent = parent;
        this->_priority = priority;
        // this->_nodes = Node::loadNode(perms);
        this->_nodes = {phmap::flat_hash_map<plg::string, Node, string_hash>(), 0xFFFFFFFF, false, false, true, 0};
        for (const plg::string& perm: perms)
            this->_nodes.addPerm(perm);
        Node::forceRehash(this->_nodes.nodes);
    }

    [[nodiscard]] Status hasPermission(const plg::string& perm) const
    {
        std::string_view sv(perm);
        auto ispl = std::views::split(sv, '.');
        uint64_t hashes[64];
        std::string_view names[64];
        int i = 0;
        for (auto&& s : ispl)
        {
            const auto ptr = s.empty() ? nullptr : &*s.begin();
            const auto len = s.size();
            hashes[i] = XXH3_64bits(ptr, len);
            names[i] = std::string_view(ptr, len);
            ++i;
        }

        return _hasPermission(names, hashes, i);
    }

    Status _hasPermission(const std::string_view names[], const uint64_t hashes[], const int sz) const
    {
        const Group* i = this;

        while (i)
        {
            Status temp = i->_nodes._hasPermission(names, hashes, sz);
            if (temp == Status::PermNotFound) i = i->_parent;
            else return temp;
        }
        return Status::PermNotFound;
    }
};
