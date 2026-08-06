#pragma once
#include "thread.h"
#include <functional>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>

#if defined(__cpp_lib_move_only_function)
    using move_func_t = std::move_only_function<void()>;
#else
    using move_func_t = std::function<void()>;
#endif

class AsyncTaskQueue {
    std::mutex                              _mtx;
    std::condition_variable                  _cv;
    std::queue<move_func_t>                  _tasks;
    std::atomic<bool>                        _running{true};
    xthread                                  _worker;
    bool                                     _started{false};

public:
    AsyncTaskQueue() = default;
    ~AsyncTaskQueue() = default;

    AsyncTaskQueue(const AsyncTaskQueue&) = delete;
    AsyncTaskQueue& operator=(const AsyncTaskQueue&) = delete;
    AsyncTaskQueue(AsyncTaskQueue&&) = delete;
    AsyncTaskQueue& operator=(AsyncTaskQueue&&) = delete;

    void Start() {
        if (_started)
            return;

        _worker = xthread([this] { Run(); });
        _started = true;
    }

    template<typename Fn>
    void Enqueue(Fn&& task) {
        {
            std::lock_guard lock(_mtx);
            _tasks.push(std::forward<Fn>(task));
        }
        _cv.notify_one();
    }

    void Run() {
        while (_running.load(std::memory_order_acquire)) {
            std::queue<move_func_t> local;
            {
                std::unique_lock lock(_mtx);
                _cv.wait(lock, [&] {
                    return !_tasks.empty() || !_running.load(std::memory_order_acquire);
                });
                if (!_running.load(std::memory_order_acquire) && _tasks.empty())
                    break;
                local.swap(_tasks);
            }

            while (!local.empty()) {
                try {
                    local.front()();
                } catch (...) {}
                local.pop();
            }
        }
    }

    void Shutdown() {
        bool expected = true;
        if (!_running.compare_exchange_strong(expected, false,
                std::memory_order_release, std::memory_order_relaxed))
            return;
        _cv.notify_all();

        if (_worker) {
            _worker.join();
        }
    }

    bool IsRunning() const {
        return _running.load(std::memory_order_acquire);
    }

    bool HasWorker() const {
        return _started;
    }
};