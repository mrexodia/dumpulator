import struct

import unicorn

from .dumpulator import Dumpulator, syscall_functions
from .native import *


def syscall(func):
    syscall_functions[func.__name__] = func
    return func


@syscall
def ZwQueryVirtualMemory(dp: Dumpulator,
                         ProcessHandle: HANDLE,
                         BaseAddress: PVOID,
                         MemoryInformationClass: MEMORY_INFORMATION_CLASS,
                         MemoryInformation: PVOID,
                         MemoryInformationLength: SIZE_T,
                         ReturnLength: P(SIZE_T)
                         ):
    assert ProcessHandle == dp.NtCurrentProcess()
    return STATUS_SUCCESS


@syscall
def ZwAllocateVirtualMemory(dp: Dumpulator,
                            ProcessHandle: HANDLE,
                            BaseAddress: P(PVOID),
                            ZeroBits: ULONG_PTR,
                            RegionSize: P(SIZE_T),
                            AllocationType: ULONG,
                            Protect: ULONG
                            ):
    assert ProcessHandle == dp.NtCurrentProcess()
    assert AllocationType == MEM_COMMIT
    assert Protect == PAGE_READWRITE
    base = dp.read_ptr(BaseAddress.ptr)
    size = dp.read_ptr(RegionSize.ptr)
    dp._uc.mem_map(base, size, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
    return STATUS_SUCCESS


@syscall
def ZwWriteFile(dp: Dumpulator,
                FileHandle: HANDLE,
                Event: HANDLE,
                ApcRoutine: P(IO_APC_ROUTINE),
                ApcContext: PVOID,
                IoStatusBlock: P(IO_STATUS_BLOCK),
                Buffer: PVOID,
                Length: ULONG,
                ByteOffset: P(LARGE_INTEGER),
                Key: P(ULONG)
                ):
    data = Buffer.read_str(Length)
    print(data)
    return STATUS_SUCCESS


@syscall
def ZwQueryInformationThread(dp: Dumpulator,
                             ThreadHandle: HANDLE,
                             ThreadInformationClass: THREADINFOCLASS,
                             ThreadInformation: PVOID,
                             ThreadInformationLength: ULONG,
                             ReturnLength: P(ULONG)
                             ):
    if ThreadInformationClass == THREADINFOCLASS.ThreadDynamicCodePolicyInfo:
        assert ThreadInformationLength == 4
        assert ReturnLength == 0
        dp.write_ulong(ThreadInformation, 0)
        return STATUS_SUCCESS
    raise Exception()

@syscall
def ZwOpenSection(dp: Dumpulator):
    return STATUS_NOT_IMPLEMENTED

@syscall
def ZwMapViewOfSection(dp: Dumpulator):
    return STATUS_NOT_IMPLEMENTED

@syscall
def ZwClose(dp: Dumpulator):
    return STATUS_NOT_IMPLEMENTED

@syscall
def ZwSetEvent(dp: Dumpulator):
    return STATUS_NOT_IMPLEMENTED

@syscall
def ZwTerminateProcess(dp: Dumpulator,
                       ProcessHandle: HANDLE,
                       ExitStatus: ULONG):
    assert ProcessHandle == 0 or ProcessHandle == dp.NtCurrentProcess()
    dp.stop(ExitStatus)
    return STATUS_SUCCESS

@syscall
def ZwTerminateThread(dp: Dumpulator,
                      ThreadHandle: HANDLE,
                      ExitStatus: ULONG):
    assert ThreadHandle == dp.NtCurrentThread()
    return STATUS_NOT_IMPLEMENTED

@syscall
def ZwSetInformationThread(dp: Dumpulator):
    return STATUS_NOT_IMPLEMENTED

@syscall
def ZwOpenKey(dp: Dumpulator):
    return STATUS_NOT_IMPLEMENTED

@syscall
def ZwWow64IsProcessorFeaturePresent(dp: Dumpulator,
                                     ProcessorFeature: ULONG
                                     ):
    return 1

@syscall
def ZwQueryVolumeInformationFile(dp: Dumpulator,
                                 FileHandle: HANDLE,
                                 IoStatusBlock: P(IO_STATUS_BLOCK),
                                 FsInformation: PVOID,
                                 Length: ULONG,
                                 FsInformationClass: FS_INFORMATION_CLASS
                                 ):
    # TODO: implement
    return STATUS_SUCCESS