#include "debug.h"

inline ULONG
STDAPIVCALLTYPE
DbgPrintNop(
	_In_z_ _Printf_format_string_ PCSTR Format,
	...
)
{
	return 0;
}

#ifdef _WIN64
#pragma comment(linker, "/EXPORT:DebugPrintf=DebugPrintf")
#else
#pragma comment(linker, "/EXPORT:DebugPrintf=_DebugPrintf")
#endif // _WIN64

extern "C" decltype(&DbgPrint) DebugPrintf = DbgPrintNop;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    return TRUE;
}