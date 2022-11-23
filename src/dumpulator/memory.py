from enum import Enum, IntFlag, Flag
from typing import Any, List, Dict, Union
import bisect

PAGE_SIZE = 0x1000

class MemoryProtect(Flag):
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

    def __str__(self):
        result = self.name
        if result is None:
            result = super().__str__().replace(f"{self.__class__.__name__}.", "")
        return result

class MemoryType(Enum):
    UNDEFINED = 0
    MEM_IMAGE = 0x1000000
    MEM_MAPPED = 0x40000
    MEM_PRIVATE = 0x20000

class MemoryState(Enum):
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    MEM_FREE = 0x10000

class MemoryRegion:
    def __init__(self, start: int, size: int, protect: MemoryProtect = MemoryProtect.PAGE_NOACCESS, type: MemoryType = MemoryType.MEM_PRIVATE, info: Any = None):
        assert start & 0xFFF == 0
        assert size & 0xFFF == 0
        self.start = start
        self.size = size
        self.protect = protect
        self.type = type
        self.info = info
        self.commit_count = 0

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
        result = f"{hex(self.start)}[{hex(self.size)}]"
        if self.info is not None:
            result += f" ({self.info})"
        return result

    def __repr__(self) -> str:
        return f"MemoryRegion({hex(self.start)}, {hex(self.size)}, {self.protect}, {self.type}, {repr(self.info)})"

    def pages(self):
        for page in range(self.start, self.end, PAGE_SIZE):
            yield page

class PageManager:
    def commit(self, addr: int, size: int, protect: MemoryProtect) -> None:
        raise NotImplementedError()

    def decommit(self, addr: int, size: int) -> None:
        raise NotImplementedError()

    def protect(self, addr: int, size: int, protect: MemoryProtect) -> None:
        raise NotImplementedError()

class MemoryBasicInformation:
    def __init__(self, base: int, allocation_base: int, allocation_protect: MemoryProtect):
        self.base = base
        self.allocation_base = allocation_base
        self.allocation_protect = allocation_protect
        self.region_size: int = PAGE_SIZE
        self.state: MemoryState = None
        self.protect: MemoryProtect = None
        self.type: MemoryType = None
        self.info: Any = None

    def __str__(self):
        return f"MemoryBasicInformation(base: {hex(self.base)}, allocation_base: {hex(self.allocation_base)}, region_size: {hex(self.region_size)}, state: {self.state}, protect: {self.protect}, type: {self.type})"

class MemoryManager:
    def __init__(self, page_manager: PageManager, minimum = 0x10000, maximum = 0x7fffffff0000, granularity = 0x10000):
        self._page_manager = page_manager
        self._minimum = minimum
        self._maximum = maximum
        self._granularity = granularity
        self._regions: List[MemoryRegion] = []
        self._committed: Dict[int, MemoryRegion] = {}

    def find_region(self, region: Union[MemoryRegion, int]):
        if isinstance(region, int):
            region = MemoryRegion(self.align_page(region), 0)
        index = bisect.bisect_right(self._regions, region)
        if index == 0:
            return None
        else:
            closest = self._regions[index - 1]
            if region in closest:
                return closest
            else:
                return None

    def find_commit(self, addr: int):
        addr = self.align_page(addr)
        return self._committed.get(addr, None)

    def align_page(self, addr: int):
        mask = PAGE_SIZE - 1
        return (addr + mask) & ~mask

    def align_allocation(self, addr: int):
        mask = self._granularity - 1
        return (addr + mask) & ~mask

    def find_free(self, size: int):
        assert size > 0 and self.align_page(size) == size
        base = self._minimum
        while base < self._maximum:
            info = self.query(base)
            assert info.base == base
            if info.state == MemoryState.MEM_FREE and info.region_size >= size and self.align_allocation(base) == base:
                return info.base
            base += info.region_size
        return None

    def reserve(self, start: int, size: int, protect: MemoryProtect, type: MemoryType = MemoryType.MEM_PRIVATE, info: Any = None):
        assert isinstance(protect, MemoryProtect)
        assert isinstance(type, MemoryType)
        assert size > 0 and self.align_page(size) == size
        assert self.align_allocation(start) == start
        region = MemoryRegion(start, size, protect, type, info)
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
        assert self.align_allocation(start) == start

        parent_region = self.find_region(start)
        if parent_region is None:
            raise KeyError(f"Could not find parent for {hex(start)}")
        if parent_region.start != start:
            raise KeyError(f"You can only release the whole parent region")

        if all([page in self._committed for page in parent_region.pages()]):
            self._page_manager.decommit(parent_region.start, parent_region.size)
            for page in parent_region.pages():
                del self._committed[page]
                parent_region.commit_count -= 1
        else:
            for page in parent_region.pages():
                if page in self._committed:
                    self._page_manager.decommit(page, PAGE_SIZE)
                    del self._committed[page]
                    parent_region.commit_count -= 1
        assert parent_region.commit_count == 0
        self._regions.remove(parent_region)

    def commit(self, start: int, size: int, protect: MemoryProtect = MemoryProtect.UNDEFINED):
        assert isinstance(protect, MemoryProtect)
        assert size > 0 and self.align_page(size) == size
        assert self.align_page(start) == start
        region = MemoryRegion(start, size)
        parent_region = self.find_region(region)
        if parent_region is None:
            raise KeyError(f"Could not find parent for {region}")

        if protect == MemoryProtect.UNDEFINED:
            protect = parent_region.protect

        if parent_region.commit_count == 0:
            assert all([page not in self._committed for page in region.pages()])
            self._page_manager.commit(region.start, region.size, protect)
            for page in region.pages():
                self._committed[page] = MemoryRegion(page, PAGE_SIZE, protect, parent_region.type)
                parent_region.commit_count += 1
        else:
            for page in region.pages():
                if page in self._committed:
                    page_region = self._committed[page]
                    if page_region.protect != protect:
                        self._page_manager.protect(page, PAGE_SIZE, protect)
                        page_region.protect = protect
                else:
                    self._page_manager.commit(page, PAGE_SIZE, protect)
                    self._committed[page] = MemoryRegion(page, PAGE_SIZE, protect, parent_region.type)
                    parent_region.commit_count += 1

    def decommit(self, start: int, size: int):
        assert size > 0 and self.align_page(size) == size
        assert self.align_page(start) == start
        region = MemoryRegion(start, size)
        parent_region = self.find_region(region)
        if parent_region is None:
            raise KeyError(f"Could not find parent for {region}")

        if all([page in self._committed for page in region.pages()]):
            self._page_manager.decommit(region.start, region.size)
            for page in self._committed:
                del self._committed[page]
                parent_region.commit_count -= 1
        else:
            for page in region.pages():
                if page in self._committed:
                    self._page_manager.decommit(page, PAGE_SIZE)
                    del self._committed[page]
                    parent_region.commit_count -= 1

    def protect(self, start: int, size: int, protect: MemoryProtect):
        assert isinstance(protect, MemoryProtect)
        assert size > 0 and self.align_page(size) == size
        assert self.align_page(start) == start
        region = MemoryRegion(start, size)
        parent_region = self.find_region(region)
        if parent_region is None:
            raise KeyError(f"Could not find parent for {region}")

        # Make sure all pages in the region are commited
        for page in region.pages():
            if not self._committed[page]:
                raise KeyError(f"Could not protect uncommited page {hex(page)}")

        # Change the protection
        old_protect = self._committed[region.start].protect
        self._page_manager.protect(region.start, region.size, protect)
        for page in region.pages():
            page_region = self._committed[page]
            if page_region.protect != protect:
                page_region.protect = protect

        return old_protect

    def query(self, start: int):
        start = self.align_page(start)

        region = MemoryRegion(start, 0)
        parent_region = self.find_region(region)
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
                if page == parent_region.start:
                    result.info = parent_region.info
                if page in self._committed:
                    result.state = MemoryState.MEM_COMMIT
                    commited_page = self._committed[page]
                    result.protect = commited_page.protect
                    result.type = commited_page.type
                    if commited_page.info:
                        result.info = commited_page.info
                    assert commited_page.type == parent_region.type
                else:
                    result.state = MemoryState.MEM_RESERVE
                    result.protect = MemoryProtect.UNDEFINED
                    result.type = parent_region.type
                    # If no pages are commited in this parent region we can bail early
                    if parent_region.commit_count == 0:
                        result.region_size = parent_region.size
                        break
            else:
                commited_page = self._committed.get(page, None)
                if result.state == MemoryState.MEM_RESERVE:
                    if commited_page is not None:
                        break
                    result.region_size += PAGE_SIZE
                elif result.state == MemoryState.MEM_COMMIT:
                    if commited_page is not None and commited_page.type == result.type and commited_page.protect == result.protect:
                        result.region_size += PAGE_SIZE
                    else:
                        break
                else:
                    assert False  # unreachable
        return result

    def map(self):
        addr = self._minimum
        regions: List[MemoryBasicInformation] = []
        while addr < self._maximum:
            info = self.query(addr)
            regions.append(info)
            addr += info.region_size
        return regions