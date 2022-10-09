import unittest
from typing import Dict

from dumpulator.memory import *

class MockPageManager(PageManager):
    def __init__(self):
        self.pages: Dict[int, MemoryProtect] = {}

    def commit(self, addr: int, size: int, protect: MemoryProtect) -> None:
        print(f"commit({hex(addr)}, {hex(size)}, {protect})")
        for page in range(addr, addr + size, PAGE_SIZE):
            self.pages[page] = protect

    def decommit(self, addr: int, size: int) -> None:
        print(f"decommit({hex(addr)}, {hex(size)})")
        for page in range(addr, addr + size, PAGE_SIZE):
            del self.pages[page]

    def protect(self, addr: int, size: int, protect: MemoryProtect) -> None:
        print(f"protect({hex(addr)}, {hex(size)}, {protect})")
        for page in range(addr, addr + size, PAGE_SIZE):
            assert page in self.pages
            self.pages[page] = protect

class TestMemoryManager(unittest.TestCase):
    def setUp(self) -> None:
        self.pm = MockPageManager()
        self.mm = MemoryManager(self.pm)

    def test_reserve(self):
        self.mm.reserve(0x20000, 0x10000, MemoryProtect.PAGE_READWRITE)
        assert self.pm.pages == {}
        assert self.mm.query(0x20000).region_size == 0x10000
        assert self.mm.query(0x22000).region_size == 0x10000 - 0x2000
        self.assertRaises(KeyError, lambda: self.mm.reserve(0x10000, 0x100000, MemoryProtect.PAGE_READWRITE))
        self.assertRaises(KeyError, lambda: self.mm.reserve(0x0, 0x2000, MemoryProtect.PAGE_NOACCESS))
        self.assertRaises(KeyError, lambda: self.mm.reserve(self.mm._maximum, 0x1000, MemoryProtect.PAGE_READWRITE))
        self.mm.reserve(0x30000, 0x2000, MemoryProtect.PAGE_READONLY)
        assert self.pm.pages == {}
        assert self.mm.query(0x30000).region_size == 0x2000

    def test_commit(self):
        self.mm.reserve(0x20000, 0x30000, MemoryProtect.PAGE_NOACCESS)
        self.mm.commit(0x20000, 0x2000, MemoryProtect.PAGE_READWRITE)
        assert self.pm.pages == {
            0x20000: MemoryProtect.PAGE_READWRITE,
            0x21000: MemoryProtect.PAGE_READWRITE,
        }
        info = self.mm.query(0x20000)
        assert info.base == 0x20000
        assert info.allocation_base == 0x20000
        assert info.allocation_protect == MemoryProtect.PAGE_NOACCESS
        assert info.region_size == 0x2000
        assert info.state == MemoryState.MEM_COMMIT
        assert info.protect == MemoryProtect.PAGE_READWRITE
        assert info.type == MemoryType.MEM_PRIVATE
        info = self.mm.query(0x23000)
        assert info.base == 0x23000
        assert info.allocation_base == 0x20000
        assert info.allocation_protect == MemoryProtect.PAGE_NOACCESS
        assert info.region_size == 0x30000 - 0x3000
        assert info.state == MemoryState.MEM_RESERVE
        assert info.protect == MemoryProtect.UNDEFINED
        assert info.type == MemoryType.MEM_PRIVATE

    def test_protect(self):
        # Protect parent region that doesn't exist
        self.assertRaises(KeyError, lambda: self.mm.protect(0x20000, 0x5000, MemoryProtect.PAGE_NOACCESS))
        # Reserve the region
        self.mm.reserve(0x20000, 0x5000, MemoryProtect.PAGE_READWRITE)
        # Protect uncommited pages
        self.assertRaises(KeyError, lambda: self.mm.protect(0x20000, 0x2000, MemoryProtect.PAGE_EXECUTE_READ))
        # Commit part of the region (use parent protection)
        self.mm.commit(0x20000, 0x2000, MemoryProtect.UNDEFINED)
        assert self.pm.pages == {
            0x20000: MemoryProtect.PAGE_READWRITE,
            0x21000: MemoryProtect.PAGE_READWRITE,
        }
        info = self.mm.query(0x20000)
        assert info.protect == MemoryProtect.PAGE_READWRITE
        assert info.region_size == 0x2000
        # Change the protection
        old_protect = self.mm.protect(0x20000, 0x2000, MemoryProtect.PAGE_EXECUTE_READ)
        assert old_protect == info.protect
        assert self.pm.pages == {
            0x20000: MemoryProtect.PAGE_EXECUTE_READ,
            0x21000: MemoryProtect.PAGE_EXECUTE_READ,
        }
        info = self.mm.query(0x20000)
        assert info.protect == MemoryProtect.PAGE_EXECUTE_READ
        # Commit the whole region (overrides the protection)
        self.mm.commit(0x20000, 0x5000, MemoryProtect.PAGE_EXECUTE_READWRITE)
        assert self.pm.pages == {
            0x20000: MemoryProtect.PAGE_EXECUTE_READWRITE,
            0x21000: MemoryProtect.PAGE_EXECUTE_READWRITE,
            0x22000: MemoryProtect.PAGE_EXECUTE_READWRITE,
            0x23000: MemoryProtect.PAGE_EXECUTE_READWRITE,
            0x24000: MemoryProtect.PAGE_EXECUTE_READWRITE,
        }
        info = self.mm.query(0x20000)
        assert info.region_size == 0x5000
        assert info.protect == MemoryProtect.PAGE_EXECUTE_READWRITE

if __name__ == "__main__":
    unittest.main()
