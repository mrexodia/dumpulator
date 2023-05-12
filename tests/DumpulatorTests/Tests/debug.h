#pragma once

#include "phnt.h"

#define WIDEN_EXPAND(str) L ## str
#define WIDEN(str) WIDEN_EXPAND(str)

#ifdef __cplusplus
// Helper function to directly call NtDisplayString with a string
// This simplifies the trace output of Dumpulator
template<size_t Count>
void DebugPrint(const wchar_t(&str)[Count])
{
	UNICODE_STRING ustr{ (Count - 1) * 2, Count * 2, (PWSTR)str };
	NtDisplayString(&ustr);
}
#else
static void DebugPrint(const wchar_t* str)
{
	int len = 0;
	while (str[len] != L'\0')
		len++;
	UNICODE_STRING ustr;
	ustr.Length = len * 2;
	ustr.MaximumLength = (len + 1) * 2;
	ustr.Buffer = (PWSTR)str;
	NtDisplayString(&ustr);
}
#endif // __cplusplus

extern "C" decltype(&DbgPrint) DebugPrintf;