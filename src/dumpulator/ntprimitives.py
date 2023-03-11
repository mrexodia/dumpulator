import struct
import ctypes
from typing import Optional, Annotated
from enum import Enum
from dataclasses import dataclass

class Architecture(object):
    def __init__(self, x64: bool):
        self._x64 = x64

    @property
    def x64(self):
        return self._x64

    def ptr_size(self):
        return 8 if self._x64 else 4

    def ptr_type(self, t=None):  # TODO: implement type
        return ctypes.c_uint64 if self._x64 else ctypes.c_uint32

    def alignment(self):
        return 16 if self._x64 else 8

    def read(self, addr: int, size: int) -> bytes:
        raise NotImplementedError()

    def write(self, addr: int, data: bytes):
        raise NotImplementedError()

    def read_char(self, addr: int) -> int:
        return struct.unpack("<b", self.read(addr, 1))[0]

    def read_short(self, addr: int) -> int:
        return struct.unpack("<h", self.read(addr, 2))[0]

    def read_long(self, addr: int) -> int:
        return struct.unpack("<i", self.read(addr, 4))[0]

    def read_byte(self, addr: int) -> int:
        return struct.unpack("<B", self.read(addr, 1))[0]

    def read_ushort(self, addr: int) -> int:
        return struct.unpack("<H", self.read(addr, 2))[0]

    def read_ulong(self, addr: int) -> int:
        return struct.unpack("<I", self.read(addr, 4))[0]

    def read_ptr(self, addr: int) -> int:
        return struct.unpack("<Q" if self._x64 else "<I", self.read(addr, self.ptr_size()))[0]

    def write_char(self, addr: int, value: int):
        self.write(addr, struct.pack("<b", value))

    def write_short(self, addr: int, value: int):
        self.write(addr, struct.pack("<h", value))

    def write_long(self, addr: int, value: int):
        self.write(addr, struct.pack("<i", value))

    def write_byte(self, addr: int, value: int):
        self.write(addr, struct.pack("<B", value))

    def write_ushort(self, addr: int, value: int):
        self.write(addr, struct.pack("<H", value))

    def write_ulong(self, addr: int, value: int):
        self.write(addr, struct.pack("<I", value))

    def write_ptr(self, addr: int, value: int):
        self.write(addr, struct.pack("<Q" if self._x64 else "<I", value))

    def read_str(self, addr: int, encoding="utf-8") -> str:
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
        if self.type is None:
            return self.arch.read_ptr(self.ptr + index * self.arch.ptr_size())
        assert index == 0  # TODO: sizeof() not yet implemented
        sizeof = self.arch.ptr_size()
        ptr = self.ptr + index * sizeof
        return (
            self.type(self.arch.read_ptr(ptr), self.arch)
            if issubclass(self.type, PVOID)
            else self.type(PVOID(ptr, self.arch))
        )

    def __int__(self):
        return self.ptr

    def __eq__(self, other):
        return self.ptr == other

    def __ne__(self, other):
        return self.ptr != other

    def __str__(self):
        return hex(self.ptr)

    def read_byte_str(self, size):
        return bytes(self.read(size))

    def read_str(self, size, encoding="utf8"):
        return self.read(size).decode(encoding)

    def read_unicode_str(self):
        length = self.arch.read_ushort(self.ptr)
        ptr = self.arch.read_ptr(self.ptr + self.arch.ptr_size())
        return self.arch.read(ptr, length).decode("utf-16")

    def read_ptr(self):
        return self.arch.read_ptr(self.ptr)

    def write_ptr(self, value: int):
        return self.arch.write_ptr(self.ptr, value)

    def write_ulong(self, value: int):
        return self.arch.write_ulong(self.ptr, value)

    def read_ulong(self):
        return self.arch.read_ulong(self.ptr)

    def deref(self):
        assert self.type is not None
        return self[0]

def P(t):
    class P(PVOID):
        def __init__(self, ptr, mem_read):
            super().__init__(ptr, mem_read)
            self.type = t
    return P

# Note: this is very WIP
class ArchStream:
    def __init__(self, ptr: PVOID):
        self.ptr = ptr
        self.pos = 0

    @property
    def x64(self):
        return self.ptr.arch.ptr_size() == 8

    def skip(self, size):
        self.pos += size

    def read(self, size):
        data = self.ptr.arch.read(self.ptr.ptr + self.pos, size)
        self.pos += size
        return data

    def read_ushort(self):
        return struct.unpack("<H", self.read(2))[0]

    def read_ulong(self):
        return struct.unpack("<I", self.read(4))[0]

    def read_ptr(self, ptrtype=None):
        ptr = struct.unpack("<Q" if self.x64 else "<I", self.read(self.ptr.arch.ptr_size()))[0]
        m = PVOID(ptr, self.ptr.arch)
        m.type = ptrtype
        return m

class Int(int):
    def __str__(self):
        return f"0x{self:X}"

# Actual primitives
class UCHAR(Int):
    def __new__(cls, value):
        return Int.__new__(cls, value & 0xFF)

class CHAR(Int):
    def __new__(cls, value):
        value = value & 0xFF
        if value & 0x80 != 0:
            value = -((~value) & 0xFF)
        return Int.__new__(cls, value)

class USHORT(Int):
    def __new__(cls, value):
        return Int.__new__(cls, value & 0xFFFF)

class ULONG(Int):
    def __new__(cls, value):
        return Int.__new__(cls, value & 0xFFFFFFFF)

class LONG(Int):
    def __new__(cls, value):
        value = value & 0xFFFFFFFF
        if value & 0x80000000 != 0:
            value = -((~value) & 0xFFFFFFFF)
        return Int.__new__(cls, value)

class ULONG_PTR(Int):
    pass

class SIZE_T(Int):
    pass

class HANDLE(Int):
    pass

# TODO: how does this work in 32 bit?
class ULONG64(Int):
    pass

# Alias types
class ULONGLONG(ULONG64):
    pass

class BYTE(UCHAR):
    pass

class RTL_ATOM(USHORT):
    pass

class NTSTATUS(ULONG):
    pass

class LANGID(USHORT):
    pass

class ALPC_HANDLE(HANDLE):
    pass

class NOTIFICATION_MASK(ULONG):
    pass

class SECURITY_INFORMATION(ULONG):
    pass

class EXECUTION_STATE(ULONG):
    pass

class SE_SIGNING_LEVEL(BYTE):
    pass

class ACCESS_MASK(ULONG):
    pass

class WNF_CHANGE_STAMP(ULONG):
    pass

class KAFFINITY(ULONG_PTR):
    pass

# TODO: should probably be bool
class BOOLEAN(BYTE):
    pass

class LOGICAL(ULONG):
    pass

class LCID(ULONG):
    pass

class PSID(PVOID):
    pass

class PWSTR(PVOID):
    pass

def make_global(t):
    globals().update(t.__members__)

# Some unsupported enum
class LATENCY_TIME(Enum):
    LT_DONT_CARE = 0
    LT_LOWEST_LATENCY = 1
make_global(LATENCY_TIME)

@dataclass
class SAL:
    annotation: str
    comment: str = ""

    def __str__(self):
        return self.annotation
