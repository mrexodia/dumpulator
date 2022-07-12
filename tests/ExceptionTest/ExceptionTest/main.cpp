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

static void debugPrint(const wchar_t* str)
{
	UNICODE_STRING ustr;
	RtlInitUnicodeString(&ustr, str);
	NtDisplayString(&ustr);
}
ROUND_TO_PAGES(0x1234)
static void debugPrint(const char* str)
{
#ifdef _DEBUG
	char copy[256];
	lstrcpyA(copy, str);
	lstrcatA(copy, "\n");
	DWORD w = 0;
	WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), copy, lstrlenA(copy), &w, nullptr);
#endif // _DEBUG

	ANSI_STRING astr;
	RtlInitAnsiString(&astr, str);
	UNICODE_STRING ustr;
	RtlAnsiStringToUnicodeString(&ustr, &astr, TRUE);
	NtDisplayString(&ustr);
}

static LONG WINAPI VectoredHandler(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	debugPrint(__FUNCTION__);
	return EXCEPTION_CONTINUE_SEARCH;
}

static LONG WINAPI ContinueHandler(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	debugPrint(__FUNCTION__);
	return EXCEPTION_CONTINUE_SEARCH;
}

static LPTOP_LEVEL_EXCEPTION_FILTER previousFilter;

static LONG WINAPI ExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	debugPrint(__FUNCTION__);
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
	{
#ifdef _WIN64
		ExceptionInfo->ContextRecord->Rip++;
#else
		ExceptionInfo->ContextRecord->Eip++;
#endif // _WIN64
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

static int __try_filter(unsigned int code, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	debugPrint(__FUNCTION__);
	const auto& er = *ExceptionInfo->ExceptionRecord;
	if (er.ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er.ExceptionInformation[1] == 0xDEADF00D)
	{
		return EXCEPTION_EXECUTE_HANDLER;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

int main()
{
	debugPrint(__FUNCTION__);
	AddVectoredExceptionHandler(1, VectoredHandler);
	AddVectoredContinueHandler(1, ContinueHandler);
	previousFilter = SetUnhandledExceptionFilter(ExceptionFilter);

	__try
	{
		*((size_t*)0xDEADF00D) = 0;
	}
	__except (__try_filter(GetExceptionCode(), GetExceptionInformation()))
	{
		debugPrint("__except handler");
	}

	__debugbreak();
}