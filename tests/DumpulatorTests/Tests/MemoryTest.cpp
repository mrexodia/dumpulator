#include "debug.h"

extern "C" __declspec(dllexport) bool Memory_PartialReleaseTest()
{
	PVOID Base = 0;
	SIZE_T RegionSize = 0x1c0000;
	auto status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, MEM_RESERVE, PAGE_READWRITE);
	DebugPrintf("status: 0x%08X, base: %p, size: %p\n", status, Base, RegionSize);
	if (!NT_SUCCESS(status))
		return false;
	
	SIZE_T PartialSize = RegionSize - 0x10000;
	status = NtFreeVirtualMemory(NtCurrentProcess(), &Base, &PartialSize, MEM_RELEASE);
	DebugPrintf("status: 0x%08X, base: %p, size: %p\n", status, Base, PartialSize);
	if (!NT_SUCCESS(status))
		return false;
	
	SIZE_T PageSize = 0x1000;
	PVOID PartialBase = (char*)Base + PartialSize;
	status = NtAllocateVirtualMemory(NtCurrentProcess(), &PartialBase, 0, &PageSize, MEM_COMMIT, PAGE_READWRITE);
	DebugPrintf("status: 0x%08X, base: %p, size: %p\n", status, PartialBase, PageSize);
	if (!NT_SUCCESS(status))
		return false;
	return true;
}

extern "C" __declspec(dllexport) bool Memory_MiddleReleaseTest()
{
	PVOID Base = 0;
	SIZE_T RegionSize = 0x30000;
	auto status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, MEM_RESERVE, PAGE_READWRITE);
	DebugPrintf("status: 0x%08X, base: %p, size: %p\n", status, Base, RegionSize);
	if (!NT_SUCCESS(status))
		return false;
	
	SIZE_T MiddleSize = 0x10000;
	PVOID MiddleBase = (char*)Base + 0x10000;
	status = NtFreeVirtualMemory(NtCurrentProcess(), &MiddleBase, &MiddleSize, MEM_RELEASE);
	DebugPrintf("status: 0x%08X, base: %p, size: %p\n", status, MiddleBase, MiddleSize);
	if (!NT_SUCCESS(status))
		return false;
	return true;
}