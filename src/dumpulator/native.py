import struct
import ctypes
import traceback
from typing import Optional

from .ntenums import *
from .ntprimitives import *
from .ntstructs import *

STATUS_SUCCESS = 0
STATUS_NOT_IMPLEMENTED = 0xC0000002
STATUS_INVALID_HANDLE = 0xC0000008
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_PRIVILEGE_NOT_HELD = 0xC0000061

DBG_PRINTEXCEPTION_C = 0x40010006

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x4

# ntioapi.h
FILE_SUPERSEDED = 0x00000000
FILE_OPENED = 0x00000001
FILE_CREATED = 0x00000002
FILE_OVERWRITTEN = 0x00000003
FILE_EXISTS = 0x00000004
FILE_DOES_NOT_EXIST = 0x00000005

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
    def load_regs(self, regs):
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

class EXTRA_CONTEXT_INFO(ctypes.Structure):
    _fields_ = [
        ("UnknownFeatures1", ctypes.c_uint32),
        ("StackAllocationSize", ctypes.c_uint32),
        ("UnknownFeatures2", ctypes.c_uint32),
        ("ContextSize", ctypes.c_uint32),
        ("Unknown3", ctypes.c_uint32),
        ("Unknown4", ctypes.c_uint32),
    ]
assert ctypes.sizeof(EXTRA_CONTEXT_INFO) == 0x18
