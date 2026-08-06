#pragma once

#include <plg/source_location.hpp>
#include <plg/plugin.hpp>

template<const char* Name, class Sig>
class ListenerManager;

template<const char* Name, class Ret, class... Args>
class ListenerManager<Name, Ret(*)(Args...)> {
public:
    ListenerManager() = default;
    ~ListenerManager() = default;

    using Func = Ret(*)(Args...);

    struct HandlerSet {
        std::vector<Func> handlers;
        std::vector<int> priorities;
    };

    Status Register(const Func& handler, int priority = 0) {
        if (!handler)
            return Status::CallbackInvalid;

        std::unique_lock lock(m_mutex);

        auto old = m_state;
        if (old && std::ranges::any_of(old->handlers, [&](const auto& h){ return h == handler; }))
            return Status::CallbackAlreadyExist;

        auto fresh = std::make_shared<HandlerSet>(old ? *old : HandlerSet{});
        auto it = std::ranges::upper_bound(fresh->priorities, priority,
            [](int p, int cur){ return p > cur; });

        auto index = std::distance(fresh->priorities.begin(), it);
        fresh->handlers.insert(fresh->handlers.begin() + index, handler);
        fresh->priorities.insert(fresh->priorities.begin() + index, priority);

        m_state = std::move(fresh);
        return Status::Success;
    }

    Status Unregister(const Func& handler) {
        std::unique_lock lock(m_mutex);

        auto old = m_state;
        if (!old)
            return Status::CallbackNotFound;

        auto it = std::ranges::find(old->handlers, handler);
        if (it == old->handlers.end())
            return Status::CallbackNotFound; // no copy made for a no-op

        auto index = std::distance(old->handlers.begin(), it);
        auto fresh = std::make_shared<HandlerSet>(*old);
        fresh->handlers.erase(fresh->handlers.begin() + index);
        fresh->priorities.erase(fresh->priorities.begin() + index);

        m_state = std::move(fresh);
        return Status::Success;
    }

    auto operator()(Args... args, const plg::source_location& loc = plg::source_location::current()) {
        [[maybe_unused]] plg::Scope zone(Name, loc);

    	auto snapshot = Get();
        return Dispatch(snapshot ? snapshot->handlers : std::span<const Func>{}, std::forward<Args>(args)...);
    }

    void Clear() {
        std::unique_lock lock(m_mutex);
        m_state.reset();
    }

    std::shared_ptr<const HandlerSet> Get() const {
        std::shared_lock lock(m_mutex);
        return m_state;
    }

    bool Empty() const {
        std::shared_lock lock(m_mutex);
        return !m_state || m_state->handlers.empty();
    }

protected:
    void Dispatch(std::span<const Func> funcs, Args&&... args) requires (!std::same_as<Ret, bool>) {
        for (const auto& f : funcs)
            f(std::forward<Args>(args)...);
    }

    bool Dispatch(std::span<const Func> funcs, Args&&... args) requires (std::same_as<Ret, bool>) {
        bool result = false;
        for (const auto& f : funcs)
            result |= !f(std::forward<Args>(args)...);
        return result;
    }

private:
    std::shared_ptr<const HandlerSet> m_state;
    mutable std::shared_mutex m_mutex;
};