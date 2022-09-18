from typing import Any, Type, TypeVar


class FileHandleObj:
    def __init__(self, path):
        self.path = path
        self.file_offset = 0

    def __str__(self):
        return f"{type(self).__name__}(path: {self.path}, file_offset {self.file_offset})"


class SpecialFileHandleObj(FileHandleObj):
    def __init__(self, path, special):
        super().__init__(path)
        self.special = special


class HandleManager:
    def __init__(self):
        self.handles = {}
        self.free_handles = []
        self.base_handle = 0x100
        self.handle_count = 0

    T = TypeVar('T')

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
            self.free_handles.append(handle_value)
            return True
        return False

    # copies object ref to a new key (handle) and increments ref_count
    def duplicate(self, handle_value: int) -> int:
        assert handle_value in self.handles.keys()
        handle_object = self.handles[handle_value]
        new_handle_value = self.__find_free_handle()
        self.handles[new_handle_value] = handle_object
        return new_handle_value
