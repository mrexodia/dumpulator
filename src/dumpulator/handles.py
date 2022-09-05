
class Handle:
    def __init__(self, data: dict):
        self.data = data
        self.ref_count = 1


class HandleManager:
    def __init__(self):
        self.handles = {}
        self.base_handle = 0x100
        self.handle_count = 0

    # probably a better way to do this
    # starting from the base_handle, finds the next free available key
    def __find_free_handle(self) -> int:
        curr_key: int = self.base_handle
        while True:
            if curr_key not in self.handles.keys():
                return curr_key
            else:
                curr_key += 0x4

    # create new handle object and returns key
    def new(self, data: dict) -> int:
        curr_handle = self.__find_free_handle()
        self.handles[curr_handle] = Handle(data)
        self.handle_count += 1
        return curr_handle

    # used to add predefined known handles
    def add(self, handle: int, data: dict = {}):
        assert handle not in self.handles.keys()
        self.handles[handle] = Handle(data)
        self.handle_count += 1

    # returns any object data held for the handle
    def get(self, handle: int) -> dict:
        assert handle in self.handles.keys()
        return self.handles[handle].data

    def valid(self, handle: int) -> bool:
        return handle in self.handles.keys()

    # decrements ref_count and removes the key from the dict
    def close(self, handle: int) -> bool:
        assert handle in self.handles.keys()
        self.handles[handle].ref_count -= 1
        del self.handles[handle]
        self.handle_count -= 1

    # copies object ref to a new key (handle) and increments ref_count
    def duplicate(self, handle: int) -> int:
        assert handle in self.handles.keys()
        handle_object = self.handles[handle]
        handle_object.ref_count += 1
        new_handle = self.__find_free_handle()
        self.handles[new_handle] = handle_object
        self.handle_count += 1
        return new_handle
