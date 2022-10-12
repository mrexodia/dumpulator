#include <Windows.h>

//extern "C" uintptr_t __cdecl _threadhandle(void);

int EntryPoint(void* peb)
{
#ifndef _WIN64
    __threadhandle();
#endif // _WIN64
    return 0;
}