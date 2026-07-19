#pragma once
#if defined(_WIN32)
#include <Windows.h>
#elif defined(__unix__)
#include <pthread.h>
#else
#error
#endif
#include <functional>
#include <memory>
#include <type_traits>
#include <system_error>
// #include <atomic>

struct xthread
{
#if defined(_WIN32)
	using native_handle_type = HANDLE;
	using id = DWORD;
#elif defined(__unix__)
	using native_handle_type = pthread_t;
	using id = pthread_t;
#endif
	struct creation_error : std::system_error
	{
		using std::system_error::system_error;
	};

	struct join_error : std::system_error
	{
		using std::system_error::system_error;
	};

	xthread() noexcept;
	template <typename Fn, typename... Args>
	explicit xthread(Fn&& fn, Args&&... args)
		requires std::is_invocable_v<Fn, Args...>;
	xthread(xthread&&) noexcept;
	~xthread();
	xthread& operator =(xthread&&) noexcept;
	void join();
	explicit operator bool() const noexcept;
	void detach() noexcept;
	[[nodiscard]] native_handle_type native_handle() const noexcept;
	[[nodiscard]] id get_id() const noexcept;

private:
#if defined(__cpp_lib_move_only_function)
	using called = std::move_only_function<void ()>;
#else
	using called = std::function<void ()>;
#endif
	native_handle_type m_handle;
#if defined(_WIN32)
	DWORD m_dwThreadId;
	static DWORD WINAPI stub(LPVOID lpvThreadParam) noexcept;
#elif defined(__unix__)
	static void* stub(void*) noexcept;
	inline static thread_local struct attrs
	{
		attrs();
		~attrs();
		pthread_attr_t m_attrs;
		bool m_initd;
	} t_attrs;
#endif
	// inline static constinit std::atomic<ptrdiff_t> g_stackSize = -1;
	// inline static constinit thread_local ptrdiff_t t_stackSize = -1;
};

inline xthread::xthread() noexcept :
	m_handle(native_handle_type())
#if defined(_WIN32)
	, m_dwThreadId(0)
#endif
{
}

inline xthread::~xthread()
{
	join();
}

inline xthread::operator bool() const noexcept
{
	return (bool)m_handle;
}

inline void xthread::detach() noexcept
{
	m_handle = native_handle_type();
#if defined(_WIN32)
	m_dwThreadId = 0;
#endif
}

inline auto xthread::native_handle() const noexcept -> native_handle_type
{
	return m_handle;
}

inline auto xthread::get_id() const noexcept -> id
{
#if defined(_WIN32)
	return m_dwThreadId;
#elif defined(__unix__)
	return m_handle;
#endif
};

template <typename Fn, typename... Args>
xthread::xthread(Fn&& fn, Args&&... args)
	requires std::is_invocable_v<Fn, Args...>
{
	using namespace std;
	auto clld = make_unique<called>(bind(forward<Fn>(fn), forward<Args>(args)...));
	// ptrdiff_t stackSize = t_stackSize >= 0 ? t_stackSize : g_stackSize.load(memory_order_relaxed);
	// stackSize = stackSize >= 0 ? stackSize : 0;
	constexpr size_t stackSize = 128 * 1024;
#if defined(_WIN32)
	if (m_handle = CreateThread(nullptr, stackSize, stub, clld.get(), 0, &m_dwThreadId); !m_handle)
		throw creation_error(static_cast<int>(GetLastError()), system_category(), "thread creation failed");
#elif defined(__unix__)
	pthread_attr_t* pAttrs = nullptr;
	if (stackSize > 0 && t_attrs.m_initd && pthread_attr_setstacksize(&t_attrs.m_attrs, stackSize) == 0)
		pAttrs = &t_attrs.m_attrs;
	if (int err = pthread_create(&m_handle, pAttrs, stub, clld.get()); err != 0)
		throw creation_error(err, system_category(), "thread creation failed");
#endif
	clld.release();
}
