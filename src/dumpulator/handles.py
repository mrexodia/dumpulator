from typing import Any, Dict, Optional, Type, TypeVar, List
from pathlib import Path
from dataclasses import dataclass

from .native import *

T = TypeVar('T')

class AbstractObject:
    def pretty(self, *fields: str):
        d = self.__dict__
        name = type(self).__name__
        if len(d) == 0:
            return name
        else:
            values = []
            if fields:
                for key in fields:
                    values.append(f"{key}: {d[key]}")
            else:
                for key in d.keys():
                    if not key.startswith("_"):
                        values.append(f"{key}: {d[key]}")
                dd = d
            return f"{name}({', '.join(values)})"

    def __str__(self):
        return self.pretty()

class UnknownObject(AbstractObject):
    pass

@dataclass
class UnsupportedObject(AbstractObject):
    type_name: str

@dataclass
class AbstractFileObject(AbstractObject):
    path: str

    def read(self, size: Optional[int] = None) -> bytes:
        raise NotImplementedError()

    def write(self, buffer: bytes, size: Optional[int] = None):
        raise NotImplementedError()

@dataclass
class FileObject(AbstractFileObject):
    data: Optional[bytes] = None
    file_offset: int = 0

    def __str__(self):
        return self.pretty("path", "file_offset")

    def read(self, size: Optional[int] = None) -> bytes:
        # TODO: store file access flags to handle access violations

        if self.data is None:
            return b""

        if size is None:
            data = self.data[self.file_offset:]
            self.file_offset += len(data)
        else:
            data = self.data[self.file_offset:self.file_offset+size]
            self.file_offset += len(data)
        return bytes(data)

    def write(self, buffer: bytes, size: Optional[int] = None):
        # TODO: store file creation flags to correctly handle overwrites
        # TODO: store file access flags to handle access violations

        # currently overwrites data given offset and buffer size, does not overwrite with zeros with different
        # creation options
        # incase input size differs from actual buffer size
        if self.data is None:
            if size is not None:
                self.data = buffer[:size]
                self.file_offset += size
            else:
                self.data = buffer
                self.file_offset += len(buffer)
        else:
            if size is not None:
                self.data = self.data[:self.file_offset] + buffer[:size] + self.data[self.file_offset+size:]
                self.file_offset += size
            else:
                self.data = self.data[:self.file_offset] + buffer + self.data[self.file_offset + len(buffer):]
                self.file_offset += len(buffer)

class ConsoleType(Enum):
    In = 0
    Out = 1
    Err = 2

class ConsoleFileObject(AbstractFileObject):
    def __init__(self, console_type: ConsoleType, lines: Optional[List[str]] = None):
        self.type = console_type
        # Reference: https://learn.microsoft.com/en-us/windows/console/setconsolemode
        self.mode = 0x1F7 if console_type == ConsoleType.In else 0x7
        self.lines = [] if lines is None else lines
        self.current_line = 0
        console_files = {
            ConsoleType.In: "CONIN$",
            ConsoleType.Out: "CONOUT$",
            ConsoleType.Err: "CONERR$",
        }
        super().__init__(console_files[console_type])

    def __str__(self):
        return self.pretty("path")

    def read(self, size: Optional[int] = None) -> bytes:
        assert self.type == ConsoleType.In, "cannot read from stdin"
        if len(self.lines) == 0:
            text = input("stdin: ")
        else:
            assert self.current_line < len(self.lines), "no more data"
            text = self.lines[self.current_line]
            self.current_line += 1
        text += "\r\n"
        data = text.encode("utf-8")
        assert len(data) < size
        return data

    def write(self, buffer: bytes, size: Optional[int] = None):
        assert self.type != ConsoleType.In, "cannot write to stdin"
        print(f"std{'out' if self.type == ConsoleType.Out else 'err'}: {buffer}")

@dataclass
class SectionObject(AbstractObject):
    file: FileObject

@dataclass
class ProcessTokenObject(AbstractObject):
    process_handle: int

@dataclass
class DeviceControlData:
    dp: "Dumpulator"
    code: int
    data: bytes
    io_status: Optional[int] = None
    io_information: Optional[int] = None

    # Internal state
    _index: int = 0

    def read(self, size: int):
        assert self._index + size <= len(self.data)
        data = self.data[self._index:self._index + size]
        assert len(data) == size
        self._index += size
        return data

    def skip(self, size: int):
        assert self._index + size <= len(self.data)
        self._index += size

    def read_ptr(self):
        size = self.dp.ptr_size()
        data = self.read(size)
        return struct.unpack("<Q" if size == 8 else "<I", data)[0]

    def read_ulong(self):
        data = self.read(4)
        return struct.unpack("<I", data)[0]

    def read_ulonglong(self):
        data = self.read(8)
        return struct.unpack("<Q", data)[0]

@dataclass
class DeviceObject(AbstractObject):
    path: str

    def io_control(self, dp: "Dumpulator", control: DeviceControlData) -> Optional[bytes]:
        raise NotImplementedError()

@dataclass
class EventObject(AbstractObject):
    event_type: EVENT_TYPE
    signalled: bool

class RegistryKeyObject(AbstractObject):
    def __init__(self, key: str, values: Dict[str, Any] = None):
        if values is None:
            values = {}
        self.key = key
        self.values = values

    def __str__(self):
        return self.pretty("key")

@dataclass
class ThreadObject(AbstractObject):
    entry: int
    argument: int = 0

class HandleManager:
    def __init__(self):
        self._handles = {}
        self._free_handles = []
        self._base_handle = 0x100
        self._handle_id = 0
        self._mapped_files = {}

    def __find_free_handle(self) -> int:
        def helper():
            if not self._free_handles:
                key = self._base_handle + (0x4 * self._handle_id)
                self._handle_id += 1
                return key
            return self._free_handles.pop(0)
        # Make sure the handle isn't manually added by the user
        while True:
            free_handle = helper()
            if free_handle not in self._handles:
                return free_handle

    # create new handle object and returns handle value
    def new(self, handle_data: AbstractObject) -> int:
        handle_value = self.__find_free_handle()
        self._handles[handle_value] = handle_data
        return handle_value

    # used to add predefined known handles
    def add(self, handle_value: int, handle_data: AbstractObject):
        assert handle_value not in self._handles.keys()
        self._handles[handle_value] = handle_data

    # returns any object data held for the handle
    def get(self, handle_value: int, handle_type: Type[T]) -> T:
        handle_data = self._handles.get(handle_value & ~3, None)
        if handle_data is None:
            return None
        if handle_type is not None:
            assert issubclass(handle_type, AbstractObject)
            if not isinstance(handle_data, handle_type):
                raise TypeError(f"Expected {handle_type.__name__} got {type(handle_data).__name__}")
        return handle_data

    # replaces object data for a handle (make sure there are no dangling references)
    def replace(self, handle_value: int, handle_data: AbstractObject):
        handle_value &= ~3
        assert handle_value in self._handles
        self._handles[handle_value] = handle_data

    def valid(self, handle_value: int) -> bool:
        return handle_value in self._handles.keys()

    # decrements ref_count and removes the key from the dict
    def close(self, handle_value: int) -> bool:
        if handle_value in self._handles.keys():
            del self._handles[handle_value]
            # Make sure all handles are unique
            # self.free_handles.append(handle_value)
            return True
        return False

    # copies object ref to a new key (handle) and increments ref_count
    def duplicate(self, handle_value: int) -> int:
        assert handle_value in self._handles.keys()
        handle_object = self._handles[handle_value]
        new_handle_value = self.__find_free_handle()
        self._handles[new_handle_value] = handle_object
        return new_handle_value

    def map_file(self, filename: str, handle_data: Any):
        self._mapped_files[filename.lower()] = handle_data

    def open_file(self, filename: str):
        data = self._mapped_files.get(filename.lower(), None)
        if data is None:
            return None
        return self.new(data)

    def create_file(self, filename: str, options: int) -> bool:
        # TODO: this logic should be in ZwCreateFile
        # if file is already mapped just return true
        if filename.lower() in self._mapped_files:
            return True
        # if file exists open and store contents in FileObject
        elif options == FILE_OPEN or options == FILE_OVERWRITE:
            file = Path(filename)
            if file.exists():
                with file.open("rb") as f:
                    file_data = f.read()
                    self.map_file(filename, FileObject(filename, file_data))
                return True
        # if file does not exist create a new FileObject
        elif options == FILE_CREATE:
            file = Path(filename)
            if not file.exists():
                self.map_file(filename, FileObject(filename))
                return True
        # no matter what create a new FileObject
        elif options == FILE_SUPERSEDE:
            file = Path(filename)
            if not file.exists():
                self.map_file(filename, FileObject(filename))
                return True
        # if file exists open if it doesn't create a new one then store contents in FileObject
        elif options == FILE_OPEN_IF or options == FILE_OVERWRITE_IF:
            file = Path(filename)
            if file.exists():
                with file.open("rb") as f:
                    file_data = f.read()
                    self.map_file(filename, FileObject(filename, file_data))
                    return True
            else:
                self.map_file(filename, FileObject(filename))
                return True
        return False

    def create_key(self, key: str, values: Dict[str, Any] = None):
        if values is None:
            values = {}
        data = RegistryKeyObject(key, values)
        self._mapped_files[key.lower()] = data
        return data
