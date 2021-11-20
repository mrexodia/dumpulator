#include "plugin.h"
#include <DbgHelp.h>

#pragma comment(lib, "dbghelp.lib")

static bool g_hasException = false;
static EXCEPTION_DEBUG_INFO g_exception;

PLUG_EXPORT void CBEXCEPTION(CBTYPE, PLUG_CB_EXCEPTION* exception)
{
	if (exception->Exception)
	{
		g_hasException = true;
		memcpy(&g_exception, exception->Exception, sizeof(g_exception));
	}
}

PLUG_EXPORT void CBSTOPDEBUG(CBTYPE, PLUG_CB_STOPDEBUG*)
{
	g_hasException = false;
}

static bool cbMiniDump(int argc, char* argv[])
{
	if (DbgIsRunning())
	{
		dputs("Cannot dump while running...");
		return false;
	}

	if (argc < 2)
	{
		dputs("Usage: MiniDump my.dmp");
		return false;
	}

	HANDLE hFile = CreateFileA(argv[1], GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		dprintf("Failed to create '%s'\n", argv[1]);
		return false;
	}

	CONTEXT context;
	context.ContextFlags = CONTEXT_ALL;
	GetThreadContext(DbgGetThreadHandle(), &context);

	EXCEPTION_POINTERS exceptionPointers = {};
	exceptionPointers.ContextRecord = &context;
	exceptionPointers.ExceptionRecord = &g_exception.ExceptionRecord;
	if (exceptionPointers.ExceptionRecord->ExceptionCode == 0)
	{
		auto& exceptionRecord = *exceptionPointers.ExceptionRecord;
		exceptionRecord.ExceptionCode = 0xFFFFFFFF;
		exceptionRecord.ExceptionAddress = PVOID(context.Rip);
	}

	MINIDUMP_EXCEPTION_INFORMATION exceptionInfo = {};
	exceptionInfo.ThreadId = DbgGetThreadId();
	exceptionInfo.ExceptionPointers = &exceptionPointers;
	exceptionInfo.ClientPointers = FALSE;
	auto dumpType = MINIDUMP_TYPE(MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo | MiniDumpIgnoreInaccessibleMemory);
	if (MiniDumpWriteDump(DbgGetProcessHandle(), DbgGetProcessId(), hFile, dumpType, &exceptionInfo, nullptr, nullptr))
	{
		dputs("Dump saved!");
	}
	else
	{
		dprintf("MiniDumpWriteDump failed :( LastError = %d\n", GetLastError());
	}

	CloseHandle(hFile);
	return true;
}

//Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
	_plugin_registercommand(pluginHandle, "MiniDump", cbMiniDump, true);
	return true; //Return false to cancel loading the plugin.
}

//Deinitialize your plugin data here.
void pluginStop()
{
}

//Do GUI/Menu related things here.
void pluginSetup()
{
}
