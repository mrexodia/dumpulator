import struct
from enum import Enum
from typing import Optional

def make_global(t):
    globals().update(t.__members__)

STATUS_SUCCESS = 0
STATUS_NOT_IMPLEMENTED = 0xC0000002
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_PRIVILEGE_NOT_HELD = 0xC0000061

class MEMORY_INFORMATION_CLASS(Enum):
    MemoryBasicInformation = 0
    MemoryWorkingSetInformation = 1
    MemoryMappedFilenameInformation = 2
    MemoryRegionInformation = 3
    MemoryWorkingSetExInformation = 4
    MemorySharedCommitInformation = 5
    MemoryImageInformation = 6
    MemoryRegionInformationEx = 7
make_global(MEMORY_INFORMATION_CLASS)

class THREADINFOCLASS(Enum):
    ThreadBasicInformation = 0
    ThreadTimes = 1
    ThreadPriority = 2
    ThreadBasePriority = 3
    ThreadAffinityMask = 4
    ThreadImpersonationToken = 5
    ThreadDescriptorTableEntry = 6
    ThreadEnableAlignmentFaultFixup = 7
    ThreadEventPair = 8
    ThreadQuerySetWin32StartAddress = 9
    ThreadZeroTlsCell = 10
    ThreadPerformanceCount = 11
    ThreadAmILastThread = 12
    ThreadIdealProcessor = 13
    ThreadPriorityBoost = 14
    ThreadSetTlsArrayAddress = 15
    ThreadIsIoPending = 16
    ThreadHideFromDebugger = 17
    ThreadBreakOnTermination = 18
    ThreadSwitchLegacyState = 19
    ThreadIsTerminated = 20
    ThreadLastSystemCall = 21
    ThreadIoPriority = 22
    ThreadCycleTime = 23
    ThreadPagePriority = 24
    ThreadActualBasePriority = 25
    ThreadTebInformation = 26
    ThreadCSwitchMon = 27
    ThreadCSwitchPmu = 28
    ThreadWow64Context = 29
    ThreadGroupInformation = 30
    ThreadUmsInformation = 31
    ThreadCounterProfiling = 32
    ThreadIdealProcessorEx = 33
    ThreadCpuAccountingInformation = 34
    ThreadSuspendCount = 35
    ThreadHeterogeneousCpuPolicy = 36
    ThreadContainerId = 37
    ThreadNameInformation = 38
    ThreadSelectedCpuSets = 39
    ThreadSystemThreadInformation = 40
    ThreadActualGroupAffinity = 41
    ThreadDynamicCodePolicyInfo = 42
    ThreadExplicitCaseSensitivity = 43
    ThreadWorkOnBehalfTicket = 44
    ThreadSubsystemInformation = 45
    ThreadDbgkWerReportActive = 46
    ThreadAttachContainer = 47
make_global(THREADINFOCLASS)

class FS_INFORMATION_CLASS(Enum):
    FileFsVolumeInformation = 1
    FileFsLabelInformation = 2
    FileFsSizeInformation = 3
    FileFsDeviceInformation = 4
    FileFsAttributeInformation = 5
    FileFsControlInformation = 6
    FileFsFullSizeInformation = 7
    FileFsObjectIdInformation = 8
    FileFsDriverPathInformation = 9
    FileFsVolumeFlagsInformation = 10
    FileFsSectorSizeInformation = 11
    FileFsDataCopyInformation = 12
    FileFsMetadataSizeInformation = 13
make_global(FS_INFORMATION_CLASS)

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x4

class Architecture(object):
    def __init__(self, x64):
        self._x64 = x64

    def ptr_size(self):
        return 8 if self._x64 else 4

    def read(self, addr: int, size: int) -> bytes:
        raise NotImplementedError()

    def write(self, addr: int, data: bytes):
        raise NotImplementedError()

    def read_ptr(self, addr):
        return struct.unpack("<Q" if self._x64 else "<I", self.read(addr, self.ptr_size()))[0]

    def read_ushort(self, addr):
        return struct.unpack("<H", self.read(addr, 2))[0]

    def read_ulong(self, addr):
        return struct.unpack("<I", self.read(addr, 4))[0]

    def read_long(self, addr):
        return struct.unpack("<i", self.read(addr, 4))[0]

    def read_short(self, addr):
        return struct.unpack("<h", self.read(addr, 2))[0]

    def write_ulong(self, addr, value):
        self.write(addr, struct.pack("<I", value))

    def write_long(self, addr, value):
        self.write(addr, struct.pack("<i", value))

    def write_ptr(self, addr, value):
        self.write(addr, struct.pack("<Q" if self._x64 else "<I", value))

    def read_str(self, addr, encoding="utf-8", ):
        data = self.read(addr, 512)

        # Note: this is awful
        if "-16" in encoding:
            nullidx = data.find(b'\0\0')
            if nullidx != -1:
                nullidx += 1
        else:
            nullidx = data.find(b'\0')
        if nullidx != -1:
            data = data[:nullidx]

        return data.decode(encoding)

class Int(int):
    def __str__(self):
        return f"0x{self:X}"

class PVOID:
    def __init__(self, ptr: int, arch: Architecture):
        self.ptr = ptr
        self.type: Optional[type] = None
        self.arch = arch

    def read(self, size) -> bytes:
        return self.arch.read(self.ptr, size)

    def write(self, data: bytes):
        self.arch.write(self.ptr, data)

    def __getitem__(self, index):
        return self.arch.read_ptr(self.ptr)

    def __int__(self):
        return self.ptr

    def __eq__(self, other):
        return self.ptr == other

    def __ne__(self, other):
        return self.ptr != other

    def __str__(self):
        return f"0x{self:X}"

    def read_str(self, size, encoding="utf8"):
        return self.read(size).decode(encoding)

    def read_unicode_str(self):
        length = self.arch.read_ushort(self.ptr)
        ptr = self.arch.read_ptr(self.ptr + self.arch.ptr_size())
        return self.arch.read(ptr, length).decode("utf-16")

def P(t):
    class P(PVOID):
        def __init__(self, ptr, mem_read):
            super().__init__(ptr, mem_read)
            self.type = t
    return P

class HANDLE(Int):
    pass

class SIZE_T(Int):
    pass

class ULONG_PTR(Int):
    pass

class ULONG(Int):
    def __new__(cls, value):
        return Int.__new__(cls, value & 0xFFFFFFFF)

class IO_APC_ROUTINE:
    pass

class IO_STATUS_BLOCK:
    pass

class LARGE_INTEGER:
    pass

class UNICODE_STRING:
    pass

def round_to_pages(size):
    return (size + 0xFFF) & 0xFFFFFFFFFFFFF000
