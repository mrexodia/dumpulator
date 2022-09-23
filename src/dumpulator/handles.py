from typing import Any, Dict, Optional, Type, TypeVar
from .native import *
from pathlib import Path

T = TypeVar('T')

class FileObject:
    def __init__(self, path: str, data: bytes = None):
        self.path = path
        self.data = data
        self.file_offset = 0

    def __str__(self):
        return f"{type(self).__name__}(path: {self.path}, file_offset: {self.file_offset})"

    def read(self, size: Optional[int] = None) -> bytes:
        # TODO: store file access flags to handle access violations

        if self.data is None:
            return b""

        if size is None:
            data = self.data[self.file_offset:]
            self.file_offset += len(data)
        else:
            data = self.data[self.file_offset:size]
            self.file_offset += len(data)
        return bytes(data)

    def write(self, buffer: bytes, size: Optional[int] = None):
        # TODO: store file creation flags to correctly handle overwrites
        # TODO: store file access flags to handle access violations

        # currently overwrites data given offset and buffer size, does not overwrite with zeros with different
        # creation options 
        # incase input size differs from actual buffer size
        if size is not None:
            self.data = self.data[:self.file_offset] + buffer + self.data[self.file_offset+size:]
        else:
            self.data = self.data[:self.file_offset] + buffer + self.data[self.file_offset + len(buffer):]


class SectionObject:
    def __init__(self, file: FileObject):
        self.file = file
    
    def __str__(self):
        return f"{type(self).__name__}({self.file})"

class SpecialFileObject(FileObject):
    def __init__(self, path, special):
        super().__init__(path)
        self.special = special

class ProcessTokenObject:
    def __init__(self, process_handle):
        self.process_handle = process_handle

    def __str__(self):
        return f"{type(self).__name__}({hex(self.process_handle)})"

class DeviceObject:
    def __str__(self):
        return f"{type(self).__name__}"

    def io_control(self, dp, code: int, data: bytes) -> bytes:
        raise NotImplementedError()

class RegistryKeyObject:
    def __init__(self, key: str, values: Dict[str, Any] = {}):
        self.key = key
        self.values = values
    
    def __str__(self):
        return f"{type(self).__name__}({self.key})"

class HandleManager:
    def __init__(self):
        self.handles = {}
        self.free_handles = []
        self.base_handle = 0x100
        self.handle_count = 0
        self.mapped_files = {}

    def __find_free_handle(self) -> int:
        if not self.free_handles:
            key = self.base_handle + (0x4 * self.handle_count)
            self.handle_count += 1
            return key
        return self.free_handles.pop(0)

    def __get_internal(self, handle_value: int) -> Any:
        assert handle_value in self.handles.keys()
        return self.handles.get(handle_value & ~3, None)

    # create new handle object and returns handle value
    def new(self, handle_data: Any) -> int:
        handle_value = self.__find_free_handle()
        self.handles[handle_value] = handle_data
        return handle_value

    # used to add predefined known handles
    def add(self, handle_value: int, handle_data: Any):
        assert handle_value not in self.handles.keys()
        self.handles[handle_value] = handle_data

    # returns any object data held for the handle
    def get(self, handle_value: int, handle_type: Type[T]) -> T:
        handle_data = self.__get_internal(handle_value)
        if handle_data is None:
            return None
        if handle_type is not None and not isinstance(handle_data, handle_type):
            raise TypeError(f"Expected {handle_type.__name__} got {type(handle_data).__name__}")
        return handle_data

    def valid(self, handle_value: int) -> bool:
        return handle_value in self.handles.keys()

    # decrements ref_count and removes the key from the dict
    def close(self, handle_value: int) -> bool:
        if handle_value in self.handles.keys():
            del self.handles[handle_value]
            # Make sure all handles are unique
            # self.free_handles.append(handle_value)
            return True
        return False

    # copies object ref to a new key (handle) and increments ref_count
    def duplicate(self, handle_value: int) -> int:
        assert handle_value in self.handles.keys()
        handle_object = self.handles[handle_value]
        new_handle_value = self.__find_free_handle()
        self.handles[new_handle_value] = handle_object
        return new_handle_value

    def map_file(self, filename: str, handle_data: Any):
        self.mapped_files[filename] = handle_data
    
    def open_file(self, filename: str):
        data = self.mapped_files.get(filename, None)
        if data is None:
            return None
        return self.new(data)

    def create_key(self, key: str, values: Dict[str, Any] = {}):
        data = RegistryKeyObject(key, values)
        self.mapped_files[key] = data
        return data
