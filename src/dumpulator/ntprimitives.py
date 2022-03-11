import struct
from typing import Optional
from enum import Enum

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
