import bisect
from enum import Enum, Flag
from dataclasses import dataclass, field
from typing import Any, List, Dict, Union, Optional

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

@dataclass
class MemoryRegion:
    start: int
    size: int
    protect: MemoryProtect = MemoryProtect.PAGE_NOACCESS
    type: MemoryType = MemoryType.MEM_PRIVATE
    info: Optional[Any] = None
    commit_count: int = 0

    def __post_init__(self):
        assert self.start & 0xFFF == 0
        assert self.size & 0xFFF == 0

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
        return range(self.start, self.end, PAGE_SIZE)

class PageManager:
    def commit(self, addr: int, size: int, protect: MemoryProtect) -> None:
        raise NotImplementedError()

    def decommit(self, addr: int, size: int) -> None:
        raise NotImplementedError()

    def protect(self, addr: int, size: int, protect: MemoryProtect) -> None:
        raise NotImplementedError()

    def read(self, addr: int, size: int) -> bytearray:
        raise NotImplementedError()

    def write(self, addr: int, data: bytes) -> None:
        raise NotImplementedError()

@dataclass
class MemoryBasicInformation:
    base: int
    allocation_base: int
    allocation_protect: MemoryProtect
    region_size: int = PAGE_SIZE
    state: Optional[MemoryState] = None
    protect: Optional[MemoryProtect] = None
    type: Optional[MemoryType] = None
    info: List[Any] = field(default_factory=list)

    def __str__(self):
        return f"MemoryBasicInformation(base: {hex(self.base)}, allocation_base: {hex(self.allocation_base)}, region_size: {hex(self.region_size)}, state: {self.state}, protect: {self.protect}, type: {self.type})"

@dataclass
class MemoryManager:
    _page_manager: PageManager
    _minimum: int = 0x10000
    _maximum: int = 0x7fffffff0000
    _granularity: int = 0x10000
    _regions: List[MemoryRegion] = field(default_factory=list)
    _committed: Dict[int, MemoryRegion] = field(default_factory=dict)

    def find_region(self, region: Union[MemoryRegion, int]) -> Optional[MemoryRegion]:
        if isinstance(region, int):
            region = MemoryRegion(self.containing_page(region), 0)
        index = bisect.bisect_right(self._regions, region)
        if index == 0:
            return None
        else:
            closest = self._regions[index - 1]
            if region in closest:
                return closest
            else:
                return None

    def find_commit(self, addr: int) -> Optional[MemoryRegion]:
        addr = self.containing_page(addr)
        return self._committed.get(addr, None)

    # Rounds down to the page containing this address
    @staticmethod
    def containing_page(addr: int) -> int:
        mask = PAGE_SIZE - 1
        return addr & ~mask

    # Rounds up to the nearest page size
    @staticmethod
    def align_page(addr: int) -> int:
        mask = PAGE_SIZE - 1
        return (addr + mask) & ~mask

    # Rounds up to the nearest allocation granularity
    def align_allocation(self, addr: int) -> int:
        mask = self._granularity - 1
        return (addr + mask) & ~mask

    def find_free(self, size: int, allocation_align=True) -> Optional[int]:
        assert size > 0 and self.align_page(size) == size
        base = self._minimum
        while base < self._maximum:
            info = self.query(base)
            assert info.base == base
            base += info.region_size
            if info.state == MemoryState.MEM_FREE:
                if allocation_align:
                    aligned_base = self.align_allocation(info.base)
                    diff = aligned_base - info.base
                    info.base = aligned_base
                    info.region_size -= diff
                if info.region_size >= size:
                    return info.base
        return None

    def reserve(self, start: int, size: int, protect: MemoryProtect, memory_type: MemoryType = MemoryType.MEM_PRIVATE, info: Any = None) -> None:
        assert isinstance(protect, MemoryProtect)
        assert isinstance(memory_type, MemoryType)
        assert size > 0 and self.align_page(size) == size
        assert self.align_allocation(start) == start
        region = MemoryRegion(start, size, protect, memory_type, info)
        if region.start < self._minimum or region.end > self._maximum:
            raise KeyError(f"Requested region {region} is out of bounds")

        def check_overlaps(idx):
            if 0 <= idx < len(self._regions):
                value = self._regions[idx]
                if region.overlaps(value):
                    raise KeyError(f"Requested region {region} overlaps with {value}")

        index = bisect.bisect_right(self._regions, region)
        if index == 0:
            check_overlaps(index)
        else:
            check_overlaps(index - 1)
            check_overlaps(index)
        self._regions.insert(index, region)

    def _decommit_region(self, parent_region: MemoryRegion, decommit_region: MemoryRegion):
        assert decommit_region in parent_region
        release_start = None
        release_count = 0
        for page in decommit_region.pages():
            if page in self._committed:
                release_count += 1
                if release_start is None:
                    release_start = page
            elif release_count > 0:
                self._page_manager.decommit(release_start, release_count * PAGE_SIZE)
                for i in range(release_count):
                    del self._committed[release_start + i * PAGE_SIZE]
                    parent_region.commit_count -= 1
                release_start = None
                release_count = 0

        if release_count > 0:
            self._page_manager.decommit(release_start, release_count * PAGE_SIZE)
            for i in range(release_count):
                del self._committed[release_start + i * PAGE_SIZE]
                parent_region.commit_count -= 1

    def release(self, start: int) -> None:
        assert self.align_allocation(start) == start

        parent_region = self.find_region(start)
        if parent_region is None:
            raise KeyError(f"Could not find parent for {hex(start)}")
        if parent_region.start != start:
            raise KeyError(f"You can only release the whole parent region")

        self._decommit_region(parent_region, parent_region)

        assert parent_region.commit_count == 0
        self._regions.remove(parent_region)

    def commit(self, start: int, size: int, protect: MemoryProtect = MemoryProtect.UNDEFINED) -> None:
        assert isinstance(protect, MemoryProtect)
        assert size > 0 and self.align_page(size) == size
        assert self.containing_page(start) == start
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

    def decommit(self, start: int, size: int) -> None:
        assert size > 0 and self.align_page(size) == size
        assert self.containing_page(start) == start
        region = MemoryRegion(start, size)
        parent_region = self.find_region(region)
        if parent_region is None:
            raise KeyError(f"Could not find parent for {region}")

        self._decommit_region(parent_region, region)

    def protect(self, start: int, size: int, protect: MemoryProtect) -> MemoryProtect:
        assert isinstance(protect, MemoryProtect)
        assert size > 0 and self.align_page(size) == size
        assert self.containing_page(start) == start
        region = MemoryRegion(start, size)
        parent_region = self.find_region(region)
        if parent_region is None:
            raise KeyError(f"Could not find parent for {region}")

        # Make sure all pages in the region are committed
        for page in region.pages():
            if not self._committed[page]:
                raise KeyError(f"Could not protect uncommitted page {hex(page)}")

        # Change the protection
        old_protect = self._committed[region.start].protect
        self._page_manager.protect(region.start, region.size, protect)
        for page in region.pages():
            page_region = self._committed[page]
            if page_region.protect != protect:
                page_region.protect = protect

        return old_protect

    def query(self, start: int) -> MemoryBasicInformation:
        start = self.containing_page(start)

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
        result_info = {}
        def add_info(memory_region: MemoryRegion):
            if memory_region.info is None:
                return
            if memory_region.info in result_info:
                return
            result_info[memory_region.info] = memory_region.start
        for page in parent_region.pages():
            if page < start:
                continue
            elif result is None:
                result = MemoryBasicInformation(page, parent_region.start, parent_region.protect)
                add_info(parent_region)
                if page in self._committed:
                    result.state = MemoryState.MEM_COMMIT
                    committed_page = self._committed[page]
                    result.protect = committed_page.protect
                    result.type = committed_page.type
                    add_info(committed_page)
                    assert committed_page.type == parent_region.type
                else:
                    result.state = MemoryState.MEM_RESERVE
                    result.protect = MemoryProtect.UNDEFINED
                    result.type = parent_region.type
                    # If no pages are committed in this parent region we can bail early
                    if parent_region.commit_count == 0:
                        result.region_size = parent_region.size
                        break
            else:
                committed_page = self._committed.get(page, None)
                if result.state == MemoryState.MEM_RESERVE:
                    if committed_page is not None:
                        break
                    result.region_size += PAGE_SIZE
                elif result.state == MemoryState.MEM_COMMIT:
                    if committed_page is not None and committed_page.type == result.type and committed_page.protect == result.protect:
                        result.region_size += PAGE_SIZE
                        add_info(committed_page)
                    else:
                        break
                else:
                    assert False  # unreachable
        # Only keep information starting from the current page, or the parent page if none
        if result is not None:
            result.info = []
            for info, start_addr in result_info.items():
                if start_addr >= result.base:
                    result.info.append(info)
            if len(result.info) == 0 and len(result_info) > 0:
                result.info = list(result_info.keys())[:1]

        return result

    def map(self) -> List[MemoryBasicInformation]:
        addr = self._minimum
        regions: List[MemoryBasicInformation] = []
        while addr < self._maximum:
            info = self.query(addr)
            regions.append(info)
            addr += info.region_size
        return regions

    def read(self, addr: int, size: int) -> bytearray:
        return self._page_manager.read(addr, size)

    def write(self, addr: int, data: bytes):
        return self._page_manager.write(addr, data)

    def set_region_info(self, addr: int, info: Any, *, size=0):
        region = self.find_region(addr)
        if region is None:
            return False

        if size > 0:
            for page in region.pages():
                if page < addr:
                    continue
                if page >= addr + size:
                    break
                commit = self._committed.get(page)
                if commit is not None and commit.info is None:
                    commit.info = info
        else:
            if region.info is not None:
                return False
            region.info = info
        return True
