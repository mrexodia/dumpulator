import struct
import ctypes
import typing
from typing import Optional, Annotated, Generic, TypeVar, Type, Union, SupportsInt, SupportsBytes
from enum import Enum
from dataclasses import dataclass

class Architecture:
    def __init__(self, x64: bool):
        self._x64 = x64

    @property
    def x64(self):
        return self._x64

    def ptr_size(self):
        return 8 if self._x64 else 4

    def ptr_type(self):
        return ctypes.c_uint64 if self._x64 else ctypes.c_uint32

    def alignment(self):
        return 16 if self._x64 else 8

    def read(self, addr: SupportsInt, size: int) -> bytes:
        raise NotImplementedError()

    def write(self, addr: SupportsInt, data: Union[SupportsBytes, bytes]):
        raise NotImplementedError()

    def read_char(self, addr: SupportsInt) -> int:
        return struct.unpack("<b", self.read(addr, 1))[0]

    def read_short(self, addr: SupportsInt) -> int:
        return struct.unpack("<h", self.read(addr, 2))[0]

    def read_long(self, addr: SupportsInt) -> int:
        return struct.unpack("<i", self.read(addr, 4))[0]

    def read_byte(self, addr: SupportsInt) -> int:
        return struct.unpack("<B", self.read(addr, 1))[0]

    def read_ushort(self, addr: SupportsInt) -> int:
        return struct.unpack("<H", self.read(addr, 2))[0]

    def read_ulong(self, addr: SupportsInt) -> int:
        return struct.unpack("<I", self.read(addr, 4))[0]

    def read_ptr(self, addr: SupportsInt) -> int:
        return struct.unpack("<Q" if self._x64 else "<I", self.read(addr, self.ptr_size()))[0]

    def write_char(self, addr: SupportsInt, value: int):
        self.write(addr, struct.pack("<b", value))

    def write_short(self, addr: SupportsInt, value: int):
        self.write(addr, struct.pack("<h", value))

    def write_long(self, addr: SupportsInt, value: int):
        self.write(addr, struct.pack("<i", value))

    def write_byte(self, addr: SupportsInt, value: int):
        self.write(addr, struct.pack("<B", value))

    def write_ushort(self, addr: SupportsInt, value: int):
        self.write(addr, struct.pack("<H", value))

    def write_ulong(self, addr: SupportsInt, value: int):
        self.write(addr, struct.pack("<I", value))

    def write_ptr(self, addr: SupportsInt, value: int):
        self.write(addr, struct.pack("<Q" if self._x64 else "<I", value))

    def read_str(self, addr: SupportsInt, encoding="utf-8") -> str:
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

    def read(self, size: int) -> bytes:
        return self.arch.read(self.ptr, size)

    def write(self, data: Union[SupportsBytes, bytes]):
        self.arch.write(self.ptr, data)

    def __getitem__(self, index) -> T:
        ptype = self.type
        if ptype is None:
            raise TypeError(f"No type associated with pointer")

        if P.is_ptr(ptype):
            ptr = self.ptr + index * self.arch.ptr_size()
            return ptype(self.arch, self.arch.read_ptr(ptr))
        else:
            size = Struct.sizeof(ptype, self.arch)
            ptr = self.ptr + index * size
            if issubclass(ptype, Struct):
                return ptype(self.arch, ptr)
            else:
                ctype = Struct.translate_ctype(self.arch.ptr_type(), ptype)
                size = ctypes.sizeof(ctype)
                data = self.arch.read(ptr, size)
                value = ctype.from_buffer(data)
                return ptype(value)

    def deref(self) -> T:
        return self[0]

    def __int__(self):
        return self.ptr

    def __eq__(self, other):
        return self.ptr == other

    def __ne__(self, other):
        return self.ptr != other

    def __str__(self):
        return hex(self.ptr)

    def read_byte_str(self, size: int):
        return bytes(self.read(size))

    def read_str(self, size: int, encoding="utf8"):
        return self.read(size).decode(encoding)

    def read_unicode_str(self):
        length = self.arch.read_ushort(self.ptr)
        ptr = self.arch.read_ptr(self.ptr + self.arch.ptr_size())
        return self.arch.read(ptr, length).decode("utf-16")

    def read_ptr(self):
        return self.arch.read_ptr(self.ptr)

    def write_ptr(self, value: typing.SupportsInt):
        return self.arch.write_ptr(self.ptr, int(value))

    def write_ulong(self, value: typing.SupportsInt):
        return self.arch.write_ulong(self.ptr, int(value))

    def read_ulong(self):
        return self.arch.read_ulong(self.ptr)

class PVOID(P):
    pass

# TODO: find a way to show the fields in the PyCharm debugger (properties?)
class Struct:
    def __init__(self, arch: Architecture, ptr: int = 0):
        self._hints = typing.get_type_hints(self)
        # TODO: allow 'binding' the pointer
        self._ptr = ptr
        self._arch = arch
        fields = []
        for name, t in self._hints.items():
            ctype = Struct.translate_ctype(arch.ptr_type(), t)
            if ctype is None:
                raise TypeError(f"Unsupported native type {t.__name__} for member {self.__class__.__name__}{name}")
            fields.append((name, ctype))
        self._ctype = Struct._create_type(
            self.__class__.__name__ + "_ctype",
            ctypes.Structure,
            _fields_=fields,
            _alignment_=arch.alignment()
        )
        if ptr != 0:
            data = arch.read(ptr, Struct.sizeof(self))
            self._cself = self._ctype.from_buffer_copy(data)
        else:
            self._cself = self._ctype()
        # Add properties to visualize things in the debugger
        for name in self._hints:
            object.__setattr__(self, name, property(lambda s: getattr(s, name)))

    @classmethod
    def sizeof(cls, value, arch: Optional[Architecture] = None) -> int:
        if P.is_ptr(value):
            if arch is None:
                ctype = value.arch.ptr_type()
            else:
                ctype = arch.ptr_type()
        elif isinstance(value, Struct):
            ctype = value._ctype
        elif issubclass(value, Struct):
            if arch is None:
                raise TypeError("No architecture passed")
            ctype = value(arch)._ctype
        elif isinstance(value, Int):
            if arch is None:
                raise TypeError("No architecture passed")
            ctype = Struct.translate_ctype(arch.ptr_type(), type(value))
        elif issubclass(value, Int):
            if arch is None:
                raise TypeError("No architecture passed")
            ctype = Struct.translate_ctype(arch.ptr_type(), value)
        else:
            raise NotImplementedError()
        assert ctype is not None
        return ctypes.sizeof(ctype)

    @classmethod
    def bytes(cls, value: "Struct") -> bytes:
        assert isinstance(value, Struct)
        return bytes(value)

    def __bytes__(self) -> bytes:
        return bytes(self._cself)

    # https://stackoverflow.com/questions/28552433/dynamically-create-ctypes-in-python
    @staticmethod
    def _create_type(name, *bases, **attrs):
        return type(name, bases, attrs)

    @staticmethod
    def translate_ctype(ptr_type, t: type):
        if P.is_ptr(t):
            return ptr_type
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
            return ptr_type
        else:
            return None

    def __getattribute__(self, name: str):
        if name.startswith("__"):
            return object.__getattribute__(self, name)
        elif name != "_hints" and name in self._hints:
            # Proxy the ctypes fields
            atype = self._hints[name]
            avalue = getattr(self._cself, name)
            if P.is_ptr(atype):
                return atype(self._arch, avalue)
            elif issubclass(atype, Enum):
                return atype(avalue)
            else:
                return atype(avalue)
        else:
            return object.__getattribute__(self, name)

    def __setattr__(self, name: str, value):
        if name.startswith("__"):
            object.__setattr__(self, name, value)
        elif name != "_hints" and name in self._hints:
            # TODO: support assigning pointers properly
            # TODO: support assigning enums properly
            setattr(self._cself, name, int(value))
        elif name.startswith("_") or name in self.__dict__:
            object.__setattr__(self, name, value)
        else:
            raise AttributeError(f"Unknown attribute {self.__class__.__name__}.{name}")

class Int(int):
    def __str__(self):
        return hex(self)

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

class KPRIORITY(ULONG_PTR):
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

# Some unsupported enum
class LATENCY_TIME(Enum):
    LT_DONT_CARE = 0
    LT_LOWEST_LATENCY = 1

@dataclass
class SAL:
    annotation: str
    comment: str = ""

    def __str__(self):
        return self.annotation
