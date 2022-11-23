#include "debug.h"

static int g_VectoredHandlerCount = 0;
static int g_ContinueHandlerCount = 0;
static int g_ExceptionFilterCount = 0;
static int g_TryFilterCount = 0;

static LONG WINAPI VectoredHandler(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	g_VectoredHandlerCount++;
	DebugPrint(WIDEN(__FUNCTION__));
	return EXCEPTION_CONTINUE_SEARCH;
}

static LONG WINAPI ContinueHandler(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	g_ContinueHandlerCount++;
	DebugPrint(WIDEN(__FUNCTION__));
	return EXCEPTION_CONTINUE_SEARCH;
}

static LPTOP_LEVEL_EXCEPTION_FILTER previousFilter;

static LONG WINAPI ExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	g_ExceptionFilterCount++;
	DebugPrint(WIDEN(__FUNCTION__));
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
	g_TryFilterCount++;
	DebugPrint(WIDEN(__FUNCTION__));
	const auto& er = *ExceptionInfo->ExceptionRecord;
	if (er.ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er.ExceptionInformation[1] == 0xDEADF00D)
	{
		return EXCEPTION_EXECUTE_HANDLER;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

extern "C" __declspec(dllexport) bool Exception_RegularTest()
{
	DebugPrint(WIDEN(__FUNCTION__));
	DebugPrint(L"Test VEH, SEH, VCH");
	AddVectoredExceptionHandler(1, VectoredHandler);
	AddVectoredContinueHandler(1, ContinueHandler);

	__try
	{
		*((size_t*)(uintptr_t)0xDEADF00D) = 0;
	}
	__except (__try_filter(GetExceptionCode(), GetExceptionInformation()))
	{
		DebugPrint(L"__except handler");
	}

	auto sehWorking = g_VectoredHandlerCount == 1 && g_ContinueHandlerCount == 0 && g_ExceptionFilterCount == 0 && g_TryFilterCount == 1;
	if (!sehWorking)
		DebugPrint(L"SEH not working!");
	
	g_VectoredHandlerCount = 0;
	g_ContinueHandlerCount = 0;
	g_ExceptionFilterCount = 0;
	g_TryFilterCount = 0;

	return sehWorking;
}

#if 0
extern "C" __declspec(dllexport) bool Exception_FilterTest()
{
	DebugPrint(L"Test SetUnhandledExceptionFilter");
	previousFilter = SetUnhandledExceptionFilter(ExceptionFilter);
	__debugbreak();
	DebugPrint(L"Finished!");

	auto uefWorking = g_VectoredHandlerCount == 1 && g_ContinueHandlerCount == 1 && g_ExceptionFilterCount == 1 && g_TryFilterCount == 0;
	if (!uefWorking)
		DebugPrint(L"UnhandledExceptionFilter not working!");

	g_VectoredHandlerCount = 0;
	g_ContinueHandlerCount = 0;
	g_ExceptionFilterCount = 0;
	g_TryFilterCount = 0;

	return uefWorking;
}
#endif