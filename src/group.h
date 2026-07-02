#pragma once
#include "node.h"

#include <xxhash.h>
#include <parallel_hashmap/phmap.h>
#include <plg/any.hpp>
#include <plg/string.hpp>
#include <plg/vector.hpp>

struct Group
{
	std::shared_mutex perms_lock, cookies_lock;
    std::atomic<Group*> _parent; // root of this group
    plg::string _name; // name of group
    phmap::flat_hash_map<plg::string, plg::any, string_hash, std::equal_to<>> _options; // group options aka cookies on user
    Node _nodes; // nodes of group
	int _priority; // priority of group

    Group(const plg::vector<plg::string>& perms, const plg::string& name, const int priority, Group* parent = nullptr)
    {
        this->_name = name;
        this->_parent = parent;
        this->_priority = priority;
        this->_nodes = {phmap::flat_hash_map<plg::string, Node, string_hash>(), 0xFFFFFFFF, false, false, true, 0};
        for (const plg::string& perm: perms)
            this->_nodes.addPerm(perm);
        Node::forceRehash(this->_nodes.nodes);
    }

	PLUGIFY_FORCE_INLINE void addPerm(const std::string_view& perm)
    {
    	std::unique_lock lock(perms_lock);
    	_nodes.addPerm(perm);
    }

	PLUGIFY_FORCE_INLINE bool delPerm(const std::string_view& perm, const bool recursive_delete, plg::vector<plg::string>& deleted_perms)
    {
    	std::unique_lock lock(perms_lock);
    	return _nodes.deletePerm(perm, recursive_delete, deleted_perms);
    }

	plg::vector<plg::string> dumpPerms()
    {
    	std::shared_lock lock(perms_lock);
    	plg::vector<plg::string> output_perms = Node::dumpNode(_nodes);
    	return output_perms;
    }

	PLUGIFY_FORCE_INLINE bool getCookie(const plg::string& name, plg::any& value)
    {
	    {
	    	std::shared_lock lock(cookies_lock);
	    	auto val = _options.find(name);
	    	if (val != _options.end()) {
	    		value = val->second;
	    		return true;
	    	}
	    }
    	Group* g = _parent.load();
    	if (!g)
    		return false;
    	return g->getCookie(name, value);
    }

	PLUGIFY_FORCE_INLINE void setCookie(const plg::string& name, const plg::any& value)
    {
    	std::unique_lock lock(cookies_lock);
    	_options[name] = value;
    }

	PLUGIFY_FORCE_INLINE void dumpCookies(plg::vector<plg::string> names, plg::vector<plg::any> values)
    {
    	names.clear();
    	values.clear();

    	std::shared_lock lock(cookies_lock);

    	for (const auto& [kv, vv] : _options)
    	{
    		names.push_back(kv);
    		values.push_back(vv);
    	}
    }

	PLUGIFY_FORCE_INLINE bool hasParent(const Group* g) const {
	    const Group* p = _parent.load();
    	while (p) {
    		if (p == g)
    			return true;
    		p = p->_parent.load();
    	}
    	return false;
    }

    [[nodiscard]] Status hasPermission(std::string_view perm, const bool exact, bool& w_wildcard)
    {
    	if (perm.starts_with('-'))
    		perm = perm.substr(1);
        auto ispl = std::views::split(perm, '.');
        uint64_t hashes[256];
        std::string_view names[256];
        int i = 0;
        for (auto&& s : ispl)
        {
            const auto ptr = s.empty() ? nullptr : &*s.begin();
            const auto len = s.size();
            hashes[i] = XXH3_64bits(ptr, len);
            names[i] = std::string_view(ptr, len);
            ++i;
        }

        return _hasPermission(names, hashes, i, exact, w_wildcard);
    }

    Status _hasPermission(const std::string_view names[], const uint64_t hashes[], const int sz, const bool exact, bool& w_wildcard)
    {
        const Group* i = this;
		std::shared_lock lock(this->perms_lock);
        while (i)
        {
            time_t _timestamp;
            Status temp = i->_nodes._hasPermission(names, hashes, sz, exact, w_wildcard, _timestamp);
            if (temp == Status::PermNotFound) i = i->_parent;
            else return temp;
        }
        return Status::PermNotFound;
    }
};
