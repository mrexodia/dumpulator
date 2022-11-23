import struct
import ctypes
import traceback
from typing import Optional

from .ntenums import *
from .ntprimitives import *
from .ntstructs import *

# NTSTATUS
STATUS_SUCCESS = 0
STATUS_NOT_IMPLEMENTED = 0xC0000002
STATUS_INVALID_HANDLE = 0xC0000008
STATUS_NO_SUCH_FILE = 0xC000000F
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_PRIVILEGE_NOT_HELD = 0xC0000061
STATUS_SET_CONTEXT_DENIED = 0xC000060A  # Return from NtContinue to int 29
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
STATUS_INVALID_PARAMETER = 0xC000000D
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
STATUS_NOT_FOUND = 0xC0000225
STATUS_MEMORY_NOT_ALLOCATED = 0xC00000A0
STATUS_CONFLICTING_ADDRESSES = 0xC0000018

# Exceptions
DBG_PRINTEXCEPTION_C = 0x40010006

# Memory state
MEM_COMMIT = 0x1000
MEM_FREE = 0x10000
MEM_RESERVE = 0x2000
MEM_DECOMMIT = 0x4000
MEM_RELEASE = 0x8000
MEM_DIFFERENT_IMAGE_BASE_OK = 0x800000

# Memory type
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000

# Memory protection
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOACCESS = 0x1
PAGE_READONLY = 0x2
PAGE_READWRITE = 0x4
PAGE_WRITECOPY = 0x8
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400

# Region flags
REGION_PRIVATE = 1 << 0
REGION_MAPPED_DATA = 1 << 1
REGION_MAPPED_IMAGE = 1 << 2
REGION_MAPPED_PAGEFILE = 1 << 3
REGION_MAPPED_PHYSICAL = 1 << 4
REGION_DIRECT_MAPPED = 1 << 5

# ntioapi.h
# I/O status information values for NtCreateFile/NtOpenFile
FILE_SUPERSEDED = 0x00000000
FILE_OPENED = 0x00000001
FILE_CREATED = 0x00000002
FILE_OVERWRITTEN = 0x00000003
FILE_EXISTS = 0x00000004
FILE_DOES_NOT_EXIST = 0x00000005

# Create disposition
FILE_SUPERSEDE = 0x00000000
FILE_OPEN = 0x00000001
FILE_CREATE = 0x00000002
FILE_OPEN_IF = 0x00000003
FILE_OVERWRITE = 0x00000004
FILE_OVERWRITE_IF = 0x00000005
FILE_MAXIMUM_DISPOSITION = 0x00000005

# Section flags
IMAGE_SCN_MEM_SHARED = 0x10000000
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

def round_to_pages(size):
    return (size + 0xFFF) & 0xFFFFFFFFFFFFF000

EXCEPTION_READ_FAULT = 0  # exception caused by a read
EXCEPTION_WRITE_FAULT = 1  # exception caused by a write
EXCEPTION_EXECUTE_FAULT = 8  # exception caused by an instruction fetch

CONTEXT_AMD64 = 0x00100000

CONTEXT_CONTROL = (CONTEXT_AMD64 | 0x1)
CONTEXT_INTEGER = (CONTEXT_AMD64 | 0x2)
CONTEXT_SEGMENTS = (CONTEXT_AMD64 | 0x4)
CONTEXT_FLOATING_POINT = (CONTEXT_AMD64 | 0x8)
CONTEXT_DEBUG_REGISTERS = (CONTEXT_AMD64 | 0x10)

CONTEXT_MMX_REGISTERS = CONTEXT_FLOATING_POINT

CONTEXT_FULL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)

CONTEXT_ALL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS |
               CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS)

CONTEXT_EXCEPTION_ACTIVE = 0x8000000
CONTEXT_SERVICE_ACTIVE = 0x10000000
CONTEXT_EXCEPTION_REQUEST = 0x40000000
CONTEXT_EXCEPTION_REPORTING = 0x80000000

INITIAL_MXCSR = 0x1f80  # initial MXCSR value
INITIAL_FPCSR = 0x027f  # initial FPCSR value

class M128A(ctypes.Structure):
    _fields_ = [
        ("Low",     ctypes.c_uint64),
        ("High",    ctypes.c_int64),
    ]

class XSAVE_FORMAT(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("ControlWord", ctypes.c_uint16),
        ("StatusWord", ctypes.c_uint16),
        ("TagWord", ctypes.c_ubyte),
        ("Reserved1", ctypes.c_ubyte),
        ("ErrorOpcode", ctypes.c_uint16),
        ("ErrorOffset", ctypes.c_uint32),
        ("ErrorSelector", ctypes.c_uint16),
        ("Reserved2", ctypes.c_uint16),
        ("DataOffset", ctypes.c_uint32),
        ("DataSelector", ctypes.c_uint16),
        ("Reserved3", ctypes.c_uint16),
        ("MxCsr", ctypes.c_uint32),
        ("MxCsr_Mask", ctypes.c_uint32),
        ("FloatRegisters", M128A * 8),
        ("XmmRegisters", M128A * 16),
        ("Reserved4", ctypes.c_ubyte * 96),
    ]

class XMMSAVE_FORMAT(ctypes.Structure):
    _fields_ = [
        ("Header", M128A * 2),
        ("Legacy", M128A * 8),
        ("Xmm0", M128A),
        ("Xmm1", M128A),
        ("Xmm2", M128A),
        ("Xmm3", M128A),
        ("Xmm4", M128A),
        ("Xmm5", M128A),
        ("Xmm6", M128A),
        ("Xmm7", M128A),
        ("Xmm8", M128A),
        ("Xmm9", M128A),
        ("Xmm10", M128A),
        ("Xmm11", M128A),
        ("Xmm12", M128A),
        ("Xmm13", M128A),
        ("Xmm14", M128A),
        ("Xmm15", M128A),
    ]

class _CONTEXT_FLTSAVE_UNION(ctypes.Union):
    _fields_ = [
        ("Flt", XSAVE_FORMAT),
        ("Xmm", XMMSAVE_FORMAT),
    ]

class CONTEXT(ctypes.Structure):
    _pack_ = 16
    _fields_ = [
        ("P1Home", ctypes.c_uint64),
        ("P2Home", ctypes.c_uint64),
        ("P3Home", ctypes.c_uint64),
        ("P4Home", ctypes.c_uint64),
        ("P5Home", ctypes.c_uint64),
        ("P6Home", ctypes.c_uint64),
        ("ContextFlags", ctypes.c_uint32),
        ("MxCsr", ctypes.c_uint32),
        ("SegCs", ctypes.c_uint16),
        ("SegDs", ctypes.c_uint16),
        ("SegEs", ctypes.c_uint16),
        ("SegFs", ctypes.c_uint16),
        ("SegGs", ctypes.c_uint16),
        ("SegSs", ctypes.c_uint16),
        ("EFlags", ctypes.c_uint32),
        ("Dr0", ctypes.c_uint64),
        ("Dr1", ctypes.c_uint64),
        ("Dr2", ctypes.c_uint64),
        ("Dr3", ctypes.c_uint64),
        ("Dr6", ctypes.c_uint64),
        ("Dr7", ctypes.c_uint64),
        ("Rax", ctypes.c_uint64),
        ("Rcx", ctypes.c_uint64),
        ("Rdx", ctypes.c_uint64),
        ("Rbx", ctypes.c_uint64),
        ("Rsp", ctypes.c_uint64),
        ("Rbp", ctypes.c_uint64),
        ("Rsi", ctypes.c_uint64),
        ("Rdi", ctypes.c_uint64),
        ("R8", ctypes.c_uint64),
        ("R9", ctypes.c_uint64),
        ("R10", ctypes.c_uint64),
        ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64),
        ("R13", ctypes.c_uint64),
        ("R14", ctypes.c_uint64),
        ("R15", ctypes.c_uint64),
        ("Rip", ctypes.c_uint64),
        ("FltSave", _CONTEXT_FLTSAVE_UNION),
        ("VectorRegister", M128A * 26),
        ("VectorControl", ctypes.c_uint64),
        ("DebugControl", ctypes.c_uint64),
        ("LastBranchToRip", ctypes.c_uint64),
        ("LastBranchFromRip", ctypes.c_uint64),
        ("LastExceptionToRip", ctypes.c_uint64),
        ("LastExceptionFromRip", ctypes.c_uint64),
    ]

    _others = ("P1Home", "P2Home", "P3Home", "P4Home", "P5Home", "P6Home",
               "MxCsr", "VectorRegister", "VectorControl")
    _control = ("SegSs", "Rsp", "SegCs", "Rip", "EFlags")
    _integer = ("Rax", "Rcx", "Rdx", "Rbx", "Rsp", "Rbp", "Rsi", "Rdi",
                "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
    _segments = ("SegDs", "SegEs", "SegFs", "SegGs")
    _debug = ("Dr0", "Dr1", "Dr2", "Dr3", "Dr6", "Dr7",
              "DebugControl", "LastBranchToRip", "LastBranchFromRip",
              "LastExceptionToRip", "LastExceptionFromRip")
    _mmx = ("Xmm0", "Xmm1", "Xmm2", "Xmm3", "Xmm4", "Xmm5", "Xmm6", "Xmm7",
            "Xmm8", "Xmm9", "Xmm10", "Xmm11", "Xmm12", "Xmm13", "Xmm14", "Xmm15")

    # Based on: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/win32/context_amd64.py#L424
    def from_regs(self, regs):
        setattr(self, "MxCsr", regs["mxcsr"])
        # TODO: implement high xmm support
        ContextFlags = self.ContextFlags
        if (ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL:
            for key in CONTEXT._control:
                try:
                    dpname = key.lower()
                    if key.startswith("Seg"):
                        dpname = key[3:].lower()
                    setattr(self, key, regs[dpname])
                except Exception as x:
                    traceback.print_exc()
                    pass
        if (ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER:
            for key in CONTEXT._integer:
                try:
                    setattr(self, key, regs[key.lower()])
                except Exception as x:
                    traceback.print_exc()
                    pass
        if (ContextFlags & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS:
            for key in CONTEXT._segments:
                try:
                    dpname = key.lower()
                    if key.startswith("Seg"):
                        dpname = key[3:].lower()
                    setattr(self, key, regs[dpname])
                except Exception as x:
                    traceback.print_exc()
                    pass
        if (ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS:
            for key in CONTEXT._debug:
                try:
                    value = regs[key.lower()] if key.startswith("Dr") else 0
                    setattr(self, key, value)
                except Exception as x:
                    traceback.print_exc()
                    pass
        if (ContextFlags & CONTEXT_MMX_REGISTERS) == CONTEXT_MMX_REGISTERS:
            xmm = self.FltSave.Xmm
            for key in CONTEXT._mmx:
                x = regs[key.lower()]
                y = M128A()
                y.High = x >> 64
                y.Low = x - (x >> 64)
                try:
                    setattr(xmm, key, y)
                except Exception as x:
                    traceback.print_exc()
                    pass

    def to_regs(self, regs):
        setattr(self, "MxCsr", regs["mxcsr"])
        # TODO: implement high xmm support
        ContextFlags = self.ContextFlags
        if (ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL:
            for key in CONTEXT._control:
                try:
                    dpname = key.lower()
                    if key.startswith("Seg"):
                        dpname = key[3:].lower()
                    setattr(regs, dpname, getattr(self, key))
                except Exception as x:
                    traceback.print_exc()
                    pass
        if (ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER:
            for key in CONTEXT._integer:
                try:
                    setattr(regs, key.lower(), getattr(self, key))
                except Exception as x:
                    traceback.print_exc()
                    pass
        if (ContextFlags & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS:
            for key in CONTEXT._segments:
                try:
                    dpname = key.lower()
                    if key.startswith("Seg"):
                        dpname = key[3:].lower()
                    setattr(regs, dpname, getattr(self, key))
                except Exception as x:
                    traceback.print_exc()
                    pass
        if (ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS:
            for key in CONTEXT._debug:
                try:
                    if key.startswith("Dr"):
                        setattr(regs, key.lower(), getattr(self, key))
                except Exception as x:
                    traceback.print_exc()
                    pass
        if (ContextFlags & CONTEXT_MMX_REGISTERS) == CONTEXT_MMX_REGISTERS:
            # TODO implement
            pass
            """
            xmm = self.FltSave.Xmm
            for key in CONTEXT._mmx:
                x = regs[key.lower()]
                y = M128A()
                y.High = x >> 64
                y.Low = x - (x >> 64)
                try:
                    setattr(xmm, key, y)
                except Exception as x:
                    traceback.print_exc()
                    pass
            """
assert ctypes.sizeof(CONTEXT) == 0x4d0

class EXCEPTION_RECORD64(ctypes.Structure):
    _pack_ = 16
    _fields_ = [
        ("ExceptionCode", ctypes.c_int32),
        ("ExceptionFlags", ctypes.c_uint32),
        ("ExceptionRecord", ctypes.c_uint64),
        ("ExceptionAddress", ctypes.c_uint64),
        ("NumberParameters", ctypes.c_uint32),
        ("ExceptionInformation", ctypes.c_uint64 * 15),
    ]
assert ctypes.sizeof(EXCEPTION_RECORD64) == 0x98

class WOW64_FLOATING_SAVE_AREA(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ControlWord", ctypes.c_uint32),
        ("StatusWord", ctypes.c_uint32),
        ("TagWord", ctypes.c_uint32),
        ("ErrorOffset", ctypes.c_uint32),
        ("ErrorSelector", ctypes.c_uint32),
        ("DataOffset", ctypes.c_uint32),
        ("DataSelector", ctypes.c_uint32),
        ("RegisterArea", ctypes.c_uint8 * 80),
        ("Cr0NpxState", ctypes.c_uint32),
    ]

class WOW64_CONTEXT(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ControlWord", ctypes.c_uint32),
        ("Dr0", ctypes.c_uint32),
        ("Dr1", ctypes.c_uint32),
        ("Dr2", ctypes.c_uint32),
        ("Dr3", ctypes.c_uint32),
        ("Dr6", ctypes.c_uint32),
        ("Dr7", ctypes.c_uint32),
        ("FloatSave", WOW64_FLOATING_SAVE_AREA),
        ("SegGs", ctypes.c_uint32),
        ("SegFs", ctypes.c_uint32),
        ("SegEs", ctypes.c_uint32),
        ("SegDs", ctypes.c_uint32),
        ("Edi", ctypes.c_uint32),
        ("Esi", ctypes.c_uint32),
        ("Ebx", ctypes.c_uint32),
        ("Edx", ctypes.c_uint32),
        ("Ecx", ctypes.c_uint32),
        ("Eax", ctypes.c_uint32),
        ("Ebp", ctypes.c_uint32),
        ("Eip", ctypes.c_uint32),
        ("SegCs", ctypes.c_uint32),
        ("EFlags", ctypes.c_uint32),
        ("Esp", ctypes.c_uint32),
        ("SegSs", ctypes.c_uint32),
        ("ExtendedRegisters", ctypes.c_uint8 * 512),
    ]

    def from_regs(self, regs):
        # TODO: implement properly
        self.Dr0 = regs.dr0
        self.Dr1 = regs.dr1
        self.Dr2 = regs.dr2
        self.Dr3 = regs.dr3
        self.Dr6 = regs.dr6
        self.Dr7 = regs.dr7
        self.Edi = regs.edi
        self.Esi = regs.esi
        self.Ebx = regs.ebx
        self.Edx = regs.edx
        self.Ecx = regs.ecx
        self.Eax = regs.eax
        self.Ebp = regs.ebp
        self.Eip = regs.eip
        self.EFlags = regs.eflags
        self.Esp = regs.esp

        self.SegCs = regs.cs
        self.SegSs = regs.ss
        self.SegDs = regs.ds
        self.SegEs = regs.es
        self.SegFs = regs.fs
        self.SegGs = regs.gs

        # TODO: implement xmm

    def to_regs(self, regs):
        regs.dr0 = self.Dr0
        regs.dr1 = self.Dr1
        regs.dr2 = self.Dr2
        regs.dr3 = self.Dr3
        regs.dr6 = self.Dr6
        regs.dr7 = self.Dr7
        regs.edi = self.Edi
        regs.esi = self.Esi
        regs.ebx = self.Ebx
        regs.edx = self.Edx
        regs.ecx = self.Ecx
        regs.eax = self.Eax
        regs.ebp = self.Ebp
        regs.eip = self.Eip
        regs.eflags = self.EFlags
        regs.esp = self.Esp

        # TODO: implement segment switching
        # NOTE: if you update fs/gs the fs_base/gs_base will be set to 0
        assert regs.cs == self.SegCs & 0xFFFF
        assert regs.ss == self.SegSs & 0xFFFF
        assert regs.ds == self.SegDs & 0xFFFF
        assert regs.es == self.SegEs & 0xFFFF
        assert regs.fs == self.SegFs & 0xFFFF
        assert regs.gs == self.SegGs & 0xFFFF

        # TODO: implement xmm

assert ctypes.sizeof(WOW64_CONTEXT) == 0x2cc

class EXCEPTION_RECORD32(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ExceptionCode", ctypes.c_int32),
        ("ExceptionFlags", ctypes.c_uint32),
        ("ExceptionRecord", ctypes.c_uint32),
        ("ExceptionAddress", ctypes.c_uint32),
        ("NumberParameters", ctypes.c_uint32),
        ("ExceptionInformation", ctypes.c_uint32 * 15),
    ]
assert ctypes.sizeof(EXCEPTION_RECORD32) == 0x50

# Reference: https://windows-internals.com/cet-on-windows/#7--context_ex--structure
class CONTEXT_CHUNK(ctypes.Structure):
    _fields_ = [
        ("Offset", ctypes.c_int32),
        ("Length", ctypes.c_uint32),
    ]

class CONTEXT_EX(ctypes.Structure):
    _fields_ = [
        ("All", CONTEXT_CHUNK),
        ("Legacy", CONTEXT_CHUNK),
        ("XState", CONTEXT_CHUNK),
    ]
assert ctypes.sizeof(CONTEXT_EX) == 0x18

def _RTL_PROCESS_MODULE_INFORMATION(arch: Architecture):
    class _RTL_PROCESS_MODULE_INFORMATION(ctypes.Structure):
        _alignment_ = arch.alignment()
        _fields_ = [
            ("Section", arch.ptr_type()),
            ("MappedBase", arch.ptr_type()),
            ("ImageBase", arch.ptr_type()),
            ("ImageSize", ctypes.c_uint32),
            ("Flags", ctypes.c_uint32),
            ("LoadOrderIndex", ctypes.c_uint16),
            ("InitOrderIndex", ctypes.c_uint16),
            ("LoadCount", ctypes.c_uint16),
            ("OffsetToFileName", ctypes.c_uint16),
            ("FullPathName", ctypes.c_ubyte * 256),
        ]
    return _RTL_PROCESS_MODULE_INFORMATION()

def _RTL_PROCESS_MODULES(arch: Architecture, count: int):
    class _RTL_PROCESS_MODULES(ctypes.Structure):
        _alignment_ = arch.alignment(),
        _fields_ = [
            ("NumberOfModules", ctypes.c_uint32),
            ("Modules", type(_RTL_PROCESS_MODULE_INFORMATION(arch)) * count)
        ]
    modules = _RTL_PROCESS_MODULES()
    modules.NumberOfModules = count
    return modules

class MEMORY_BASIC_INFORMATION32(ctypes.Structure):
    _alignment_ = 8
    _fields_ = [
        ("BaseAddress", ctypes.c_uint32),
        ("AllocationBase", ctypes.c_uint32),
        ("AllocationProtect", ctypes.c_uint32),
        ("RegionSize", ctypes.c_uint32),
        ("State", ctypes.c_uint32),
        ("Protect", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
    ]

class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _alignment_ = 8
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64),
        ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", ctypes.c_uint32),
        ("PartitionId", ctypes.c_uint16),
        ("RegionSize", ctypes.c_uint64),
        ("State", ctypes.c_uint32),
        ("Protect", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
    ]

def MEMORY_BASIC_INFORMATION(arch: Architecture):
    if arch.ptr_size() == 8:
        return MEMORY_BASIC_INFORMATION64()
    else:
        return MEMORY_BASIC_INFORMATION32()

def MEMORY_REGION_INFORMATION(arch: Architecture):
    class MEMORY_REGION_INFORMATION(ctypes.Structure):
        _alignment_ = arch.alignment()
        _fields_ = [
            ("AllocationBase", arch.ptr_type()),
            ("AllocationProtect", ctypes.c_uint32),
            ("Flags", ctypes.c_uint32),
            ("RegionSize", arch.ptr_type()),
            ("CommitSize", arch.ptr_type()),
        ]
    return MEMORY_REGION_INFORMATION()

def FILE_BASIC_INFORMATION(arch: Architecture):
    class FILE_BASIC_INFORMATION(ctypes.Structure):
        _alignment_ = arch.alignment()
        _fields_ = [
            ("CreationTime", ctypes.c_uint64),
            ("LastAccessTime", ctypes.c_uint64),
            ("LastWriteTime", ctypes.c_uint64),
            ("ChangeTime", ctypes.c_uint64),
            ("Flags", ctypes.c_uint32),
        ]
    return FILE_BASIC_INFORMATION()

def P(t):
    class P(PVOID):
        def __init__(self, ptr, mem_read):
            super().__init__(ptr, mem_read)
            self.type = t
    return P
