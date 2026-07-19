#include "thread.h"

using namespace std;

xthread::xthread( xthread &&other ) noexcept
{
	m_handle = other.m_handle;
	other.m_handle = native_handle_type();
#if defined(_WIN32)
	m_dwThreadId = other.m_dwThreadId;
	other.m_dwThreadId = 0;
#endif
}

xthread &xthread::operator =( xthread &&other ) noexcept
{
	m_handle = other.m_handle;
	other.m_handle = native_handle_type();
#if defined(_WIN32)
	m_dwThreadId = other.m_dwThreadId;
	other.m_dwThreadId = 0;
#endif
	return *this;
}

void xthread::join()
{
	if( !*this )
		return;
#if defined(_WIN32)
	if( WaitForSingleObject( m_handle, INFINITE ) != WAIT_OBJECT_0 )
		throw join_error( static_cast<int>(GetLastError()), system_category(), "failed to join a thread" );
	m_dwThreadId = 0;
#elif defined(__unix__)
	if( int err = pthread_join( m_handle, nullptr ); err )
		throw join_error( err, system_category(), "failed to join a thread" );
#endif
	m_handle = native_handle_type();
}

#if defined(_WIN32)

DWORD WINAPI xthread::stub( LPVOID lpvThreadParam ) noexcept
{
	(*unique_ptr<called>( static_cast<called*>(lpvThreadParam) ))();
	return 0;
}

#elif defined(__unix__)

void *xthread::stub( void *param ) noexcept
{
	(*unique_ptr<called>( static_cast<called*>(param) ))();
	return nullptr;
}

xthread::attrs::attrs() :
	m_initd( pthread_attr_init( &m_attrs ) == 0 )
{
}

xthread::attrs::~attrs()
{
	if( m_initd )
		pthread_attr_destroy( &m_attrs );
}

#endif