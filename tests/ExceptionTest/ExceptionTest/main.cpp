#include <cstdio>
#include <Windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

extern "C"
NTSYSCALLAPI
NTSTATUS
NTAPI
NtDisplayString(
	PUNICODE_STRING String
);

#define WIDEN_EXPAND(str) L ## str
#define WIDEN(str) WIDEN_EXPAND(str)

// Helper function to directly call NtDisplayString with a string
// This simplifies the trace output of dumpulator
template<size_t Count>
void debugPrint(const wchar_t(&str)[Count])
{
	UNICODE_STRING ustr{ (Count - 1) * 2, Count * 2, (PWSTR)str };
	NtDisplayString(&ustr);
}

static LONG WINAPI VectoredHandler(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	debugPrint(WIDEN(__FUNCTION__));
	return EXCEPTION_CONTINUE_SEARCH;
}

static LONG WINAPI ContinueHandler(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	debugPrint(WIDEN(__FUNCTION__));
	return EXCEPTION_CONTINUE_SEARCH;
}

static LPTOP_LEVEL_EXCEPTION_FILTER previousFilter;

static LONG WINAPI ExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	debugPrint(WIDEN(__FUNCTION__));
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
	{
#ifdef _WIN64
		ExceptionInfo->ContextRecord->Rip++;
#else
		ExceptionInfo->ContextRecord->Eip++;
#endif // _WIN64
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return previousFilter(ExceptionInfo);
}

static int __try_filter(unsigned int code, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	debugPrint(WIDEN(__FUNCTION__));
	const auto& er = *ExceptionInfo->ExceptionRecord;
	if (er.ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er.ExceptionInformation[1] == 0xDEADF00D)
	{
		return EXCEPTION_EXECUTE_HANDLER;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

int main()
{
	debugPrint(L"Test VEH, SEH, VCH");
	AddVectoredExceptionHandler(1, VectoredHandler);
	AddVectoredContinueHandler(1, ContinueHandler);

	__try
	{
		*((size_t*)(uintptr_t)0xDEADF00D) = 0;
	}
	__except (__try_filter(GetExceptionCode(), GetExceptionInformation()))
	{
		debugPrint(L"__except handler");
	}

	debugPrint(L"Test SetUnhandledExceptionFilter");
	previousFilter = SetUnhandledExceptionFilter(ExceptionFilter);
	__debugbreak();
}