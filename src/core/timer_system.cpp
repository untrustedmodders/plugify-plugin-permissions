#include "timer_system.h"

void TimerSystem::RunFrame() {
	std::scoped_lock lock(m_mutex);

	const auto timestamp = static_cast<double>(time(nullptr));

	while (!m_timers.empty()) {
		auto it = m_timers.begin();

		if (timestamp >= it->executeTime) {
			it->exec = true;
			it->callback(it->id, it->userData);
			it->exec = false;

			if (it->repeat && !it->kill) {
				auto node = m_timers.extract(it);
				node.value().executeTime = timestamp + node.value().delay;
				m_timers.insert(std::move(node));
				continue;
			}

			m_timers.erase(it);
		} else {
			break;
		}
	}
}

uint32_t TimerSystem::CreateTimer(double delay, TimerCallback callback, TimerFlag flags, const plg::vector<plg::any>& userData) {
	std::scoped_lock lock(m_mutex);

	const auto timestamp = static_cast<double>(time(nullptr));

	// Enforce minimum delay to prevent immediate execution and iterator invalidation
	uint32_t id = m_nextId++;
	m_timers.emplace(id, flags & TimerFlag::Repeat, false, false, timestamp, timestamp + delay, delay, callback, userData);
	return id;
}

void TimerSystem::KillTimer(uint32_t id) {
	std::scoped_lock lock(m_mutex);

	auto it = std::find_if(m_timers.begin(), m_timers.end(), [id](const Timer& timer) {
		return timer.id == id;
	});

	if (it != m_timers.end()) {
		if (it->exec) {
			it->kill = true;
		} else {
			m_timers.erase(it);
		}
	}
}

void TimerSystem::RescheduleTimer(uint32_t id, double newDelay) {
	std::scoped_lock lock(m_mutex);

	auto it = std::find_if(m_timers.begin(), m_timers.end(), [id](const Timer& timer) {
		return timer.id == id;
	});

	if (it != m_timers.end()) {
		if (!it->exec) {
			auto node = m_timers.extract(it);
			node.value().delay = newDelay;
			node.value().executeTime = static_cast<double>(time(nullptr)) + newDelay;
			m_timers.insert(std::move(node));
		}
	}
}