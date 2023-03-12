import struct
import ctypes
import typing
from typing import Optional, Annotated, Generic, TypeVar, Type
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
        # TODO: safely read the memory
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


T = TypeVar("T")


class P(Generic[T]):
    _ptr_ = True

    def __init__(self, arch: Architecture, ptr: int = 0):
        self.arch = arch
        self.ptr = ptr

    @property
    def type(self) -> Type[T]:
        try:
            # https://github.com/Stewori/pytypes/blob/ff82bf5a6c9cc1159ac2bf817bae8aa4141e88fc/pytypes/type_util.py#L182
            args = object.__getattribute__(self, "__orig_class__")
        except AttributeError as e:
            return None
        t, = typing.get_args(args)
        if t is type(None):
            raise TypeError("P[None] is not allowed")
        return t

    @classmethod
    def is_ptr(cls, tv):
        return hasattr(tv, "_ptr_")

    def read(self, size) -> bytes:
        return self.arch.read(self.ptr, size)

    def write(self, data: bytes):
        self.arch.write(self.ptr, data)

    def __getitem__(self, index):
        ptype = self.type
        if ptype is None:
            return self.arch.read_ptr(self.ptr + index * self.arch.ptr_size())
        else:
            assert index == 0  # TODO: sizeof() not yet implemented
            sizeof = self.arch.ptr_size()
            ptr = self.ptr + index * sizeof
            if P.is_ptr(ptype):
                return ptype(self.arch, self.arch.read_ptr(ptr))
            else:
                return ptype(PVOID(self.arch, ptr))

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
        return self[0]

class PVOID(P):
    pass

class Struct:
    def __init__(self, arch: Architecture):
        self._hints = typing.get_type_hints(self)
        self._arch = arch
        fields = []
        for name, t in self._hints.items():
            fields.append((name, self._translate_ctype(name, t)))
        self._ctype = Struct.create_type(
            self.__class__.__name__ + "_ctype",
            ctypes.Structure,
            _fields_=fields,
            _alignment_=arch.alignment()
        )
        self._cself = self._ctype()

    # https://stackoverflow.com/questions/28552433/dynamically-create-ctypes-in-python
    @staticmethod
    def _create_type(name, *bases, **attrs):
        return type(name, bases, attrs)

    def _translate_ctype(self, name: str, t: type):
        if t is P:
            return self._arch.ptr_type()
        elif issubclass(t, Enum):
            return ctypes.c_uint32
        elif issubclass(t, UCHAR):
            return ctypes.c_uint8
        elif issubclass(t, CHAR):
            return ctypes.c_int8
        elif issubclass(t, USHORT):
            return ctypes.c_uint16
        elif issubclass(t, SHORT):
            return ctypes.c_int16
        elif issubclass(t, ULONG):
            return ctypes.c_uint32
        elif issubclass(t, LONG):
            return ctypes.c_int32
        elif issubclass(t, ULONG_PTR):
            return self._arch.ptr_type()
        else:
            raise TypeError(f"Unsupported native type {t.__name__} for member {self.__class__.__name__}{name}")

    def __getattribute__(self, name):
        if name.startswith("_"):
            return object.__getattribute__(self, name)
        if name not in self._hints:
            raise AttributeError(f"Attribute not found: {self.__class__.__name__}.{name}")
        return getattr(self._cself, name)

    def __setattr__(self, name, value):
        if name.startswith("_"):
            object.__setattr__(self, name, value)
        else:
            if name not in self._hints:
                raise AttributeError(f"Attribute not found: {self.__class__.__name__}.{name}")
            return setattr(self._cself, name, value)

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

    def read_ptr(self, ptrtype: T = None) -> P[T]:
        ptr = struct.unpack("<Q" if self.x64 else "<I", self.read(self.ptr.arch.ptr_size()))[0]
        return P[ptrtype](self.ptr.arch, ptr)

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

class SHORT(Int):
    def __new__(cls, value):
        value = value & 0xFFFF
        if value & 0x8000 != 0:
            value = -((~value) & 0xFFFF)
        return Int.__new__(cls, value)

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
    def __new__(cls, value):
        return Int.__new__(cls, value & 0xFFFFFFFFFFFFFFFF)

# TODO: how does this work in 32 bit?
class ULONG64(Int):
    pass

# Alias types
class HANDLE(ULONG_PTR):  # TODO: probably shouldn't be an alias
    pass

class SIZE_T(ULONG_PTR):
    pass

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
