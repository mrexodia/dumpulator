from enum import Enum, IntFlag
from typing import Any, List, Dict
import bisect

PAGE_SIZE = 0x1000

class MemoryProtect(IntFlag):
    UNDEFINED = 0x0
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80
    PAGE_NOACCESS = 0x1
    PAGE_READONLY = 0x2
    PAGE_READWRITE = 0x4
    PAGE_WRITECOPY = 0x8
    # Only these can be combined
    PAGE_GUARD = 0x100
    PAGE_NOCACHE = 0x200
    PAGE_WRITECOMBINE = 0x400

class MemoryType(Enum):
    UNDEFINED = 0
    MEM_IMAGE = 0x1000000
    MEM_MAPPED = 0x40000
    MEM_PRIVATE = 0x20000

class MemoryState(Enum):
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    MEM_FREE = 0x10000

class MemoryBasicInformation:
    def __init__(self, base: int, allocation_base: int, allocation_protect: MemoryProtect):
        self.base = base
        self.allocation_base = allocation_base
        self.allocation_protect = allocation_protect
        self.region_size: int = PAGE_SIZE
        self.state: MemoryState = None
        self.protect: MemoryProtect = None
        self.type: MemoryType = None

    def __str__(self):
        return f"MemoryBasicInformation(base: {hex(self.base)}, allocation_base: {hex(self.allocation_base)}, region_size: {hex(self.region_size)}, state: {self.state}, protect: {self.protect}, type: {self.type})"

class MemoryRegion:
    def __init__(self, start: int, size: int, protect: MemoryProtect = MemoryProtect.PAGE_NOACCESS, type: MemoryType = MemoryType.MEM_PRIVATE):
        assert start & 0xFFF == 0
        assert size & 0xFFF == 0
        self.start = start
        self.size = size
        self.protect = protect
        self.type = type

    @property
    def end(self):
        return self.start + self.size

    def __lt__(self, other: Any):
        if isinstance(other, int):
            return self.start < other
        elif isinstance(other, MemoryRegion):
            return self.start < other.start
        raise TypeError()

    def __contains__(self, other: object) -> bool:
        if isinstance(other, int):
            return other >= self.start and other < self.end
        elif isinstance(other, MemoryRegion):
            if other.size == 0:
                return other.start >= self.start and other.end < self.end
            else:
                return other.start >= self.start and other.end <= self.end
        raise TypeError()

    def overlaps(self, other):
        if isinstance(other, MemoryRegion):
            if self.start <= other.start:
                return other.start < self.end
            else:
                return self.start < other.end
        raise TypeError()

    def __str__(self):
        return f"{hex(self.start)}[{hex(self.size)}]"

    def __repr__(self) -> str:
        return f"MemoryRegion({hex(self.start)}, {hex(self.size)}, {self.protect}, {self.type})"

    def pages(self):
        for page in range(self.start, self.end, PAGE_SIZE):
            yield page

class PageManager:
    def commit(self, addr: int, protect: MemoryProtect) -> None:
        raise NotImplementedError()

    def decommit(self, addr: int) -> None:
        raise NotImplementedError()

    def protect(self, addr: int, protect: MemoryProtect) -> None:
        raise NotImplementedError()

class MemoryManager:
    def __init__(self, page_manager: PageManager, minimum = 0x10000, maximum = 0x7fffffff0000, granularity = 0x10000):
        self._page_manager = page_manager
        self._minimum = minimum
        self._maximum = maximum
        self._granularity = granularity
        self._regions: List[MemoryRegion] = []
        self._committed: Dict[int, MemoryRegion] = {}

    def find_parent(self, region: MemoryRegion):
        index = bisect.bisect_right(self._regions, region)
        if index == 0:
            return None
        else:
            closest = self._regions[index - 1]
            if region in closest:
                return closest
            else:
                return None

    def page_align(self, addr: int):
        mask = PAGE_SIZE - 1
        return (addr + mask) & ~mask

    def allocation_align(self, addr: int):
        mask = self._granularity - 1
        return (addr + mask) & ~mask

    def reserve(self, start: int, size: int, protect: MemoryProtect, type: MemoryType = MemoryType.MEM_PRIVATE):
        assert size > 0 and self.page_align(size) == size
        assert self.allocation_align(start) == start
        region = MemoryRegion(start, size, protect, type)
        if region.start < self._minimum or region.end > self._maximum:
            raise KeyError(f"Requested region {region} is out of bounds")

        def check_overlaps(index):
            if index >= 0 and index < len(self._regions):
                value = self._regions[index]
                if region.overlaps(value):
                    raise KeyError(f"Requested region {region} overlaps with {value}")

        index = bisect.bisect_right(self._regions, region)
        if index == 0:
            check_overlaps(index)
        else:
            check_overlaps(index - 1)
            check_overlaps(index)
        self._regions.insert(index, region)

    def release(self, start: int):
        assert self.allocation_align(start) == start

        parent_region = self.find_parent(MemoryRegion(start, 0))
        if parent_region is None:
            raise KeyError(f"Could not find parent for {hex(start)}")
        if parent_region.start != start:
            raise KeyError(f"You can only release the whole parent region")

        for page in parent_region.pages():
            if page in self._committed:
                self._page_manager.decommit(page)
                del self._committed[page]
        self._regions.remove(parent_region)

    def commit(self, start: int, size: int, protect: MemoryProtect = MemoryProtect.UNDEFINED):
        assert size > 0 and self.page_align(size) == size
        assert self.page_align(start) == start
        region = MemoryRegion(start, size)
        parent_region = self.find_parent(region)
        if parent_region is None:
            raise KeyError(f"Could not find parent for {region}")

        if protect == MemoryProtect.UNDEFINED:
            protect = parent_region.protect

        for page in region.pages():
            if page in self._committed:
                self._page_manager.protect(page, protect)
                self._committed[page].protect = protect
            else:
                self._page_manager.commit(page, protect)
                self._committed[page] = MemoryRegion(page, PAGE_SIZE, protect, parent_region.type)

    def decommit(self, start: int, size: int):
        assert size > 0 and self.page_align(size) == size
        assert self.page_align(start) == start
        region = MemoryRegion(start, size)
        parent_region = self.find_parent(region)
        if parent_region is None:
            raise KeyError(f"Could not find parent for {region}")

        for page in region.pages():
            if page in self._committed:
                self._page_manager.decommit(page)
                del self._committed[page]

    def protect(self, start: int, size: int, protect: MemoryProtect):
        assert size > 0 and self.page_align(size) == size
        assert self.page_align(start) == start
        region = MemoryRegion(start, size)
        parent_region = self.find_parent(region)
        if parent_region is None:
            raise KeyError(f"Could not find parent for {region}")

        # Make sure all pages in the region are commited
        for page in region.pages():
            if not self._committed[page]:
                raise KeyError(f"Could not protect uncommited page {hex(page)}")

        # Change the protection
        old_protect = self._committed[region.start].protect
        for page in region.pages():
            self._page_manager.protect(page, protect)
            self._committed[page].protect = protect
        return old_protect

    def query(self, start: int):
        assert self.page_align(start) == start

        region = MemoryRegion(start, 0)
        parent_region = self.find_parent(region)
        if parent_region is None:
            index = bisect.bisect_right(self._regions, region)
            next_start = self._maximum
            if index < len(self._regions):
                next_start = self._regions[index].start
            result = MemoryBasicInformation(start, 0, MemoryProtect.UNDEFINED)
            result.region_size = next_start - start
            assert result.base + result.region_size == next_start
            result.state = MemoryState.MEM_FREE
            result.protect = MemoryProtect.UNDEFINED
            result.type = MemoryType.UNDEFINED
            return result

        # Reference: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery#remarks
        result: MemoryBasicInformation = None
        for page in parent_region.pages():
            if page < start:
                continue
            elif result is None:
                result = MemoryBasicInformation(page, parent_region.start, parent_region.protect)
                if page in self._committed:
                    result.state = MemoryState.MEM_COMMIT
                    commited_page = self._committed[page]
                    result.protect = commited_page.protect
                    result.type = commited_page.type
                    assert commited_page.type == parent_region.type
                else:
                    result.state = MemoryState.MEM_RESERVE
                    result.protect = MemoryProtect.UNDEFINED
                    result.type = parent_region.type
            else:
                commited_page = self._committed.get(page, None)
                if result.state == MemoryState.MEM_RESERVE:
                    result.region_size += PAGE_SIZE
                elif result.state == MemoryState.MEM_COMMIT:
                    if commited_page is not None and commited_page.type == result.type and commited_page.protect == result.protect:
                        result.region_size += PAGE_SIZE
                    else:
                        break
                else:
                    assert False  # unreachable
        return result
