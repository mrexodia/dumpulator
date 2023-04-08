import ctypes
import struct
import sys
import traceback
from enum import Enum
from typing import List, Union, NamedTuple, Callable
import inspect
from collections import OrderedDict
from dataclasses import dataclass, field

import minidump.minidumpfile as minidump
from unicorn import *
from unicorn.x86_const import *
from pefile import *

from .handles import *
from .native import *
from .details import *
from .memory import *
from .modules import *
from capstone import *
from capstone.x86 import *

syscall_functions = {}

PAGE_SIZE = 0x1000
USER_CAVE = 0x5000
FORCE_KILL_ADDR = USER_CAVE - 0x20
TSS_BASE = 0xfffff8076d963000
KERNEL_CAVE = TSS_BASE - 0x2000
IRETQ_OFFSET = 0x100
IRETD_OFFSET = IRETQ_OFFSET + 1
GDT_BASE = TSS_BASE - 0x3000

class ExceptionType(Enum):
    NoException = 0
    Memory = 1
    Interrupt = 2
    ContextSwitch = 3
    Terminate = 4

class MemoryViolation(Enum):
    Unknown = 0
    ReadUnmapped = 1
    WriteUnmapped = 2
    ExecuteUnmapped = 3
    ReadProtect = 4
    WriteProtect = 5
    ExecuteProtect = 6
    ReadUnaligned = 7
    WriteUnaligned = 8
    ExecuteUnaligned = 9

@dataclass
class ExceptionInfo:
    type: ExceptionType = ExceptionType.NoException
    # type == ExceptionType.Memory
    memory_violation: MemoryViolation = MemoryViolation.Unknown
    memory_address: int = 0
    memory_size: int = 0
    memory_value: int = 0
    # type == ExceptionType.Interrupt
    interrupt_number: int = 0

    # Internal state
    _handling: bool = False

@dataclass
class UnicornExceptionInfo(ExceptionInfo):
    final: bool = False
    code_hook_h: Optional[int] = None  # represents a `unicorn.uc_hook_h` value (from uc.hook_add)
    context: Optional[unicorn.UcContext] = None
    tb_start: int = 0
    tb_size: int = 0
    tb_icount: int = 0
    step_count: int = 0

    def __str__(self):
        return f"{self.type}, ({hex(self.tb_start)}, {hex(self.tb_size)}, {self.tb_icount})"

@dataclass
class UnicornPageManager(PageManager):
    _uc: Uc

    def commit(self, addr: int, size: int, protect: MemoryProtect) -> None:
        perms = map_unicorn_perms(protect)
        self._uc.mem_map(addr, size, perms)

    def decommit(self, addr: int, size: int) -> None:
        self._uc.mem_unmap(addr, size)

    def protect(self, addr: int, size: int, protect: MemoryProtect) -> None:
        self._uc.mem_protect(addr, size, map_unicorn_perms(protect))

    def read(self, addr: int, size: int) -> bytearray:
        return self._uc.mem_read(addr, size)

    def write(self, addr: int, data: bytes) -> None:
        if not isinstance(data, bytes):
            data = bytes(data)
        self._uc.mem_write(addr, data)

@dataclass
class LazyPage:
    addr: int
    protect: MemoryProtect
    committed: bool
    data: Optional[bytearray] = None

    @property
    def size(self):
        return PAGE_SIZE

@dataclass
class LazyPageManager(PageManager):
    child: PageManager
    total_commit: int = 0
    pages: Dict[int, LazyPage] = field(default_factory=dict)
    lazy: bool = True

    @staticmethod
    def iter_pages(addr: int, size: int):
        for i in range(0, size // PAGE_SIZE):
            page_addr = addr + i * PAGE_SIZE
            yield page_addr

    @staticmethod
    def iter_chunks(addr: int, size: int):
        # TODO: rewrite this to not be so disgusting
        page = addr & ~0xFFF
        index = addr & 0xFFF
        while True:
            if page >= addr + size:
                break
            length = min(PAGE_SIZE, (addr + size) - (page + index))
            yield page, index, length
            page += PAGE_SIZE
            index = 0

    def handle_lazy_page(self, addr: int, size: int) -> bool:
        try:
            result = False
            for page_addr, index, length in self.iter_chunks(addr, size):
                page = self.pages.get(page_addr, None)
                if page is None:
                    continue
                if not page.committed:
                    self.child.commit(page.addr, page.size, page.protect)
                    page.committed = True
                    if page.data is not None:
                        self.child.write(page.addr, page.data)
                        page.data = None
                    result = True
            return result
        except UcError as err:
            print(f"FATAL ERROR {err}: handle_lazy_page({hex(addr)}[{hex(size)}])")
            return False

    def commit(self, addr: int, size: int, protect: MemoryProtect) -> None:
        assert addr & 0xFFF == 0
        assert size & 0xFFF == 0

        if not self.lazy:
            self.child.commit(addr, size, protect)
        for page_addr in self.iter_pages(addr, size):
            assert page_addr not in self.pages
            self.pages[page_addr] = LazyPage(page_addr, protect, not self.lazy)
        self.total_commit += size

    def decommit(self, addr: int, size: int) -> None:
        assert addr & 0xFFF == 0
        assert size & 0xFFF == 0

        pages = []
        for page_addr in self.iter_pages(addr, size):
            assert page_addr in self.pages
            pages.append(self.pages[page_addr])

        if all(page.committed for page in pages):
            self.child.decommit(addr, size)
        else:
            for page in pages:
                if page.committed:
                    self.child.decommit(page.addr, page.size)

        for page_addr in self.iter_pages(addr, size):
            del self.pages[page_addr]

    def protect(self, addr: int, size: int, protect: MemoryProtect) -> None:
        assert addr & 0xFFF == 0
        assert size & 0xFFF == 0

        pages = []
        for page_addr in self.iter_pages(addr, size):
            assert page_addr in self.pages
            pages.append(self.pages[page_addr])

        if all(page.committed for page in pages):
            self.child.protect(addr, size, protect)
        else:
            for page in pages:
                if page.committed:
                    self.child.protect(page.addr, page.size, protect)

        for page in pages:
            page.protect = protect

    def read(self, addr: int, size: int) -> bytearray:
        pages = []
        for page_addr, index, length in self.iter_chunks(addr, size):
            page = self.pages.get(page_addr, None)
            if page is None:
                raise IndexError(f"Could not find page {hex(page_addr)} while reading {hex(addr)}[{hex(size)}]")
            pages.append((page, index, length))

        if all([page.committed for page, _, _ in pages]):
            return self.child.read(addr, size)
        else:
            data = bytearray(size)
            for page, index, length in pages:
                data_index = (page.addr + index) - addr
                if page.committed:
                    data[data_index:data_index + length] = self.child.read(page.addr + index, length)
                else:
                    if page.data is None:
                        page.data = bytearray(page.size)
                    data_chunk = page.data[index:index + length]
                    data[data_index:data_index + length] = data_chunk
            assert len(data) == size
            return data

    def write(self, addr: int, data: bytes) -> None:
        pages = []
        for page_addr, index, length in self.iter_chunks(addr, len(data)):
            page = self.pages.get(page_addr, None)
            if page is None:
                raise IndexError(f"Could not find page {hex(page_addr)} while writing {hex(addr)}[{hex(len(data))}]")
            pages.append((page, index, length))

        if all([page.committed for page, _, _ in pages]):
            self.child.write(addr, data)
        else:
            for page, index, length in pages:
                data_index = (page.addr + index) - addr
                data_chunk = data[data_index:data_index + length]
                assert len(data_chunk) == length
                if page.committed:
                    self.child.write(page.addr + index, data_chunk)
                else:
                    if page.data is None:
                        page.data = bytearray(page.size)
                    page.data[index:index + length] = data_chunk
                    assert len(page.data) == page.size

class SimpleTimer:
    def __init__(self):
        self.time = 0.0
        self.start()

    def start(self):
        import time
        self.time = time.perf_counter()

    def __call__(self, name: str):
        prev = self.time
        self.start()
        diff = self.time - prev
        print(f"{name}: {diff*1000:.0f}ms")

class Dumpulator(Architecture):
    def __init__(self, minidump_file, *, trace=False, quiet=False, thread_id=None, debug_logs=False):
        self._quiet = quiet
        self._debug = debug_logs
        self.sequence_id = 0

        # Load the minidump
        self._minidump = minidump.MinidumpFile.parse(minidump_file)
        if thread_id is None and self._minidump.exception is not None:
            thread_id = self._minidump.exception.exception_records[0].ThreadId
        if thread_id is None:
            thread = self._minidump.threads.threads[0]
        else:
            thread = self._find_thread(thread_id)

        self.thread_id = thread.ThreadId
        self.process_id = self._minidump.misc_info.ProcessId
        self.parent_process_id = (self.process_id // 4 + 69) * 4

        super().__init__(type(thread.ContextObject) is not minidump.WOW64_CONTEXT)
        self.addr_mask = 0xFFFFFFFFFFFFFFFF if self._x64 else 0xFFFFFFFF

        if trace:
            self.trace = open(minidump_file + ".trace", "w")
        else:
            self.trace = None

        self.last_module: Optional[Module] = None

        self._uc = Uc(UC_ARCH_X86, UC_MODE_64)

        # TODO: multiple cs instances per segment
        mode = CS_MODE_64 if self._x64 else CS_MODE_32
        self.cs = Cs(CS_ARCH_X86, mode)
        self.cs.detail = True

        self.regs = Registers(self._uc, self._x64)
        self._pages = LazyPageManager(UnicornPageManager(self._uc))
        self.memory = MemoryManager(self._pages)
        self.args = Arguments(self._uc, self._pages, self.regs, self._x64)
        self.modules = ModuleManager(self.memory)
        self._allocate_base = None
        self._allocate_size = 1024 * 1024 * 10  # NOTE: 10 megs
        self._allocate_ptr = None
        self._setup_memory()
        self.debug(f"total commit: {hex(self._pages.total_commit)}, pages: {self._pages.total_commit // PAGE_SIZE}")
        self._setup_modules()
        self.syscalls = []
        self.win32k_syscalls = []
        self._setup_syscalls()
        self._setup_emulator(thread)
        self.handles = HandleManager()
        self._setup_handles()
        self._setup_registry()
        self.stopped = False
        self.kill_exception = None
        self.exit_code = None
        self.exports = self._all_exports()
        self._exception = UnicornExceptionInfo()
        self._last_exception: Optional[UnicornExceptionInfo] = None
        self._exception_hook: Optional[Callable[[ExceptionInfo], Optional[int]]] = None
        if not self._quiet:
            print("Memory map:")
            self.print_memory()

    def print_memory(self):
        regions = self.memory.map()
        regions.pop()  # remove the last free region
        table: List[List[str]] = []
        header = ["Base", "Size", "State", "Protect", "Info"]
        table.append(header)
        for region in regions:
            entry = [""] * len(header)
            entry[0] = hex(region.base)
            entry[1] = hex(region.region_size)
            entry[2] = region.state.name
            if region.state != MemoryState.MEM_FREE:
                protect = region.protect
                if region.state == MemoryState.MEM_RESERVE:
                    protect = region.allocation_protect
                entry[3] = str(protect)
                def pretty_info(info: Any):
                    if isinstance(info, Module):
                        return f"{info.name}[{hex(info.size)}]"
                    else:
                        return str(info)
                entry[4] = ", ".join(map(pretty_info, region.info))
            table.append(entry)
        print(format_table(table))

    def _find_thread(self, thread_id):
        for i in range(0, len(self._minidump.threads.threads)):
            thread = self._minidump.threads.threads[i]
            if thread.ThreadId == thread_id:
                return thread
        raise Exception(f"Thread {hex(thread_id)} ({thread_id}) not found!")

    def debug(self, message: str):
        if self._debug:
            print(message)

    def info(self, message: str):
        if not self._quiet:
            print(message)

    @staticmethod
    def error(message: str):
        print(message)

    def _switch_segment(self, segment: SegmentRegisters, gs_base: Optional[int] = None, fs_base: Optional[int] = None):
        self.regs.cs = segment.cs
        self.regs.ss = segment.ss
        self.regs.ds = segment.ds
        self.regs.es = segment.es
        self.regs.fs = segment.fs
        self.regs.gs = segment.gs

        if gs_base is not None:
            self.regs.gs_base = gs_base
        if fs_base is not None:
            self.regs.fs_base = fs_base

    def _setup_gdt(self):
        # TODO: is the TSS actually necessary?
        self._pages.commit(TSS_BASE, PAGE_SIZE, MemoryProtect.PAGE_READWRITE)
        self._pages.commit(GDT_BASE, PAGE_SIZE, MemoryProtect.PAGE_READWRITE)
        for i in range(0, len(windows_gdt)):
            self.write(GDT_BASE + 8 * i, struct.pack("<Q", windows_gdt[i]))
        self.regs.gdtr = (0, GDT_BASE, 8 * len(windows_gdt) - 1, 0x0)

    def _setup_memory(self):
        info: minidump.MinidumpMemoryInfo
        regions: List[List[minidump.MinidumpMemoryInfo]] = []
        mask = 0xFFFFFFFFFFFFFFFF if self._x64 else 0xFFFFFFFF
        for info in self._minidump.memory_info.infos:
            info.AllocationBase &= mask
            info.BaseAddress &= mask
            if len(regions) == 0 or info.AllocationBase != regions[-1][0].AllocationBase or info.State == minidump.MemoryState.MEM_FREE:
                regions.append([])
            regions[-1].append(info)
        # NOTE: The HYPERVISOR_SHARED_DATA does not respect the allocation granularity
        potential_hv = []
        old_granularity = self.memory._granularity
        self.memory._granularity = PAGE_SIZE
        for i in range(len(regions)):
            region = regions[i]
            reserve_addr = None
            reserve_size = 0
            assert len(region) >= 1
            for j in range(len(region)):
                info = region[j]
                if reserve_addr is None:
                    reserve_addr = info.BaseAddress
                reserve_size += info.RegionSize
            info = region[0]
            if info.State == minidump.MemoryState.MEM_FREE:
                continue
            reserve_protect = MemoryProtect(info.AllocationProtect)
            reserve_type = MemoryType(info.Type.value)
            self.debug(f" reserved: {hex(reserve_addr)}, size: {hex(reserve_size)}, protect: {reserve_protect}, type: {reserve_type}")
            self.memory.reserve(reserve_addr, reserve_size, reserve_protect, reserve_type)
            if reserve_addr & (old_granularity - 1) != 0:
                potential_hv.append(reserve_addr)
            for info in region:
                emu_addr = info.BaseAddress & self.addr_mask
                if info.State == minidump.MemoryState.MEM_COMMIT:
                    protect = reserve_protect if info.Protect is None else MemoryProtect(info.Protect.value)
                    self.debug(f"committed: {hex(emu_addr)}, size: {hex(info.RegionSize)}, protect: {protect}")
                    self.memory.commit(info.BaseAddress, info.RegionSize, protect)
        self.memory._granularity = old_granularity
        memory = self._minidump.get_reader().get_buffered_reader()
        seg: minidump.MinidumpMemorySegment
        for seg in self._minidump.memory_segments_64.memory_segments:
            emu_addr = seg.start_virtual_address & self.addr_mask
            self.debug(f"initialize base: {hex(emu_addr)}, size: {hex(seg.size)}")
            memory.move(seg.start_virtual_address)
            assert memory.current_position == seg.start_virtual_address
            data = memory.read(seg.size)
            self._pages.write(emu_addr, data)
        self._pages.lazy = False

        self.memory.set_region_info(0x7ffe0000, "KUSER_SHARED_DATA")
        if len(potential_hv) == 1:
            self.memory.set_region_info(potential_hv[0], "HYPERVISOR_SHARED_DATA")
        elif len(potential_hv) > 1:
            self.debug(f"Unexpected unaligned addresses: {' '.join([hex(x) for x in potential_hv])}")

    def _setup_pebteb(self, thread):
        self.teb = thread.Teb & 0xFFFFFFFFFFFFF000

        # Handle WoW64 support
        ntdll = self.modules["ntdll.dll"]
        Wow64Transition = ntdll.find_export("Wow64Transition")
        ZwWow64ReadVirtualMemory64 = ntdll.find_export("ZwWow64ReadVirtualMemory64")
        if Wow64Transition:
            # This exists from Windows 10 1607 (Build: 14393)
            patch_addr = self.read_ptr(Wow64Transition.address)
            self.info(f"Patching Wow64Transition: [{hex(Wow64Transition.address)}] -> {hex(patch_addr)}")
            # See: https://opcode0x90.wordpress.com/2007/05/18/kifastsystemcall-hook/
            # sysenter; nop; nop; ret
            self.write(patch_addr, b"\x0F\x34\x90\x90\xC3")
            self.wow64 = True
        elif ZwWow64ReadVirtualMemory64:
            # This function exists since Windows XP
            # TODO: Implement by finding EA ???????? 3300 in wow64cpu.dll instead
            # Reference: https://github.com/x64dbg/ScyllaHide/blob/a727ac39/InjectorCLI/RemoteHook.cpp#L354-L434
            patch_addr = self.read_ptr(self.teb + 0xC0)
            self.error(f"Unsupported WoW64 OS version detected, trampoline: {hex(patch_addr)}")
            # sysenter; nop; nop; jmp [esp]
            self.write(patch_addr, b"\x0F\x34\x90\x90\xFF\x24\x24")
            self.wow64 = True
        else:
            self.wow64 = False

        # Get thread information
        for i in range(0, len(self._minidump.threads.threads)):
            thread = self._minidump.threads.threads[i]
            teb = thread.Teb & 0xFFFFFFFFFFFFF000
            tid = thread.ThreadId
            if self._x64:
                # https://www.vergiliusproject.com/kernels/x64/Windows%2011/21H2%20(RTM)/_NT_TIB
                stack_base = self.read_ptr(teb + 0x8)
                stack_limit = self.read_ptr(teb + 0x10)
                deallocation_stack = self.read_ptr(teb + 0x1478)
            else:
                # https://www.vergiliusproject.com/kernels/x86/Windows%2010/2110%2021H2%20(November%202021%20Update)/_NT_TIB
                stack_base = self.read_ptr(teb + 0x4)
                stack_limit = self.read_ptr(teb + 0x8)
                deallocation_stack = self.read_ptr(teb + 0xe0c)
            # The stack grows from base (the higher address) to limit (the lower address)
            self.memory.set_region_info(stack_base - 1, f"Stack (thread {tid})")

            teb_size = 2 * PAGE_SIZE
            self.memory.set_region_info(teb, f"TEB (thread {tid})", size=teb_size)
            if self.wow64:
                self.memory.set_region_info(teb - teb_size, f"WoW64 TEB (thread {tid})", size=teb_size)

        # https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
        # Handle PEB
        # Retrieve console handle
        if self._x64:
            # https://www.vergiliusproject.com/kernels/x64/Windows%2011/21H2%20(RTM)/_TEB
            self.peb = self.read_ptr(self.teb + 0x60)
            # https://www.vergiliusproject.com/kernels/x64/Windows%2011/21H2%20(RTM)/_PEB
            process_parameters = self.read_ptr(self.peb + 0x20)
            # https://www.vergiliusproject.com/kernels/x64/Windows%2011/21H2%20(RTM)/_RTL_USER_PROCESS_PARAMETERS
            self.console_handle = self.read_ptr(process_parameters + 0x10)
            self.stdin_handle = self.read_ptr(process_parameters + 0x20)
            self.stdout_handle = self.read_ptr(process_parameters + 0x28)
            self.stderr_handle = self.read_ptr(process_parameters + 0x30)
            self.modules.main = self.read_ptr(self.peb + 0x10)
            number_of_heaps = self.read_ulong(self.peb + 0xe8)
            process_heaps_ptr = self.read_ptr(self.peb + 0xf0)
            api_set_map = self.read_ptr(self.peb + 0x68)
            csr_shared_memory = self.read_ptr(self.peb + 0x88)
            codepage_data = self.read_ptr(self.peb + 0xa0)
            gdi_handle_table = self.read_ptr(self.peb + 0xf8)
            shim_data = self.read_ptr(self.peb + 0x2d8)
            activation_context_data = self.read_ptr(self.peb + 0x2f8)
            default_activation_context_data = self.read_ptr(self.peb + 0x308)
            leap_second_data = self.read_ptr(self.peb + 0x7b8)
        else:
            # https://www.vergiliusproject.com/kernels/x86/Windows%2010/2110%2021H2%20(November%202021%20Update)/_TEB
            self.peb = self.read_ptr(self.teb + 0x30)
            # https://www.vergiliusproject.com/kernels/x86/Windows%2010/2110%2021H2%20(November%202021%20Update)/_PEB
            process_parameters = self.read_ptr(self.peb + 0x10)
            # https://www.vergiliusproject.com/kernels/x86/Windows%2010/2110%2021H2%20(November%202021%20Update)/_RTL_USER_PROCESS_PARAMETERS
            self.console_handle = self.read_ptr(process_parameters + 0x10)
            self.stdin_handle = self.read_ptr(process_parameters + 0x18)
            self.stdout_handle = self.read_ptr(process_parameters + 0x1c)
            self.stderr_handle = self.read_ptr(process_parameters + 0x20)
            self.modules.main = self.read_ptr(self.peb + 0x8)
            number_of_heaps = self.read_ulong(self.peb + 0x88)
            process_heaps_ptr = self.read_ptr(self.peb + 0x90)
            api_set_map = self.read_ptr(self.peb + 0x38)
            csr_shared_memory = self.read_ptr(self.peb + 0x4c)
            codepage_data = self.read_ptr(self.peb + 0x58)
            gdi_handle_table = self.read_ptr(self.peb + 0x94)
            shim_data = self.read_ptr(self.peb + 0x1e8)
            activation_context_data = self.read_ptr(self.peb + 0x1f8)
            default_activation_context_data = self.read_ptr(self.peb + 0x200)
            leap_second_data = self.read_ptr(self.peb + 0x470)

        self.memory.set_region_info(self.peb, "PEB", size=PAGE_SIZE)
        if self.wow64:
            self.memory.set_region_info(self.peb - PAGE_SIZE, "WoW64 PEB", size=PAGE_SIZE)

        self.info(f"TEB: {hex(self.teb)}, PEB: {hex(self.peb)}")
        self.info(f"  ConsoleHandle: {hex(self.console_handle)}")
        self.info(f"  StandardInput: {hex(self.stdin_handle)}")
        self.info(f"  StandardOutput: {hex(self.stdout_handle)}")
        self.info(f"  StandardError: {hex(self.stderr_handle)}")

        process_heaps = []
        for i in range(0, min(number_of_heaps, 0x1000)):
            heap_ptr = self.read_ptr(process_heaps_ptr + self.ptr_size() * i)
            process_heaps.append(heap_ptr)
            self.memory.set_region_info(heap_ptr, f"Heap (ID {i})")

        self.memory.set_region_info(api_set_map, "ApiSetMap")
        self.memory.set_region_info(csr_shared_memory, "CSR shared memory")
        self.memory.set_region_info(codepage_data, "CodePage data")
        self.memory.set_region_info(gdi_handle_table, "GDI shared handle table")
        self.memory.set_region_info(shim_data, "Shim data")
        self.memory.set_region_info(activation_context_data, "Activation context data")
        self.memory.set_region_info(default_activation_context_data, "Default activation context data")
        self.memory.set_region_info(leap_second_data, "Leap second data")

    def _setup_registry(self):
        self.handles.create_key(r"\Registry\Machine\System\CurrentControlSet\Control\Nls\Sorting\Versions", {
            "": "00060305",
            "000601xx": "SortWindows61.dll",
            "000602xx": "SortWindows62.dll",
            "000603xx": "kernel32.dll",
            "FF0000xx": "SortServer2003Compat.dll",
            "FF0406xx": "SortWindows6Compat.dll",
            "FF0502xx": "SortWindows6Compat.dll",
            "000604xx": "SortWindows64.dll",
        })

    def _setup_handles(self):
        import dumpulator.ntdevices as ntdevices
        self.console = ntdevices.ConsoleDeviceObject(R"\Device\ConDrv")
        self.stdin = ConsoleFileObject(ConsoleType.In)
        self.stdout = ConsoleFileObject(ConsoleType.Out)
        self.stderr = ConsoleFileObject(ConsoleType.Err)

        if self.console_handle != 0:
            self.handles.add(self.console_handle, self.console)
        if self.stdin_handle != 0:
            self.handles.add(self.stdin_handle, self.stdin)
        if self.stdout_handle != 0:
            self.handles.add(self.stdout_handle, self.stdout)
        if self.stderr_handle != 0:
            self.handles.add(self.stderr_handle, self.stderr)

        # TODO: attempt to extract handles from the dump stream and add them as UnknownObject
        if self._minidump.handles is not None:
            by_type: Dict[str, List[minidump.MinidumpHandleDescriptor]] = {}
            minidump_handle: minidump.MinidumpHandleDescriptor
            for minidump_handle in self._minidump.handles.handles:
                type_name = minidump_handle.TypeName
                if type_name is None:
                    type_name = "Unknown"
                if type_name not in by_type:
                    by_type[type_name] = []
                by_type[type_name].append(minidump_handle)
            def default_fn(o):
                if isinstance(o, bytes):
                    return o.hex()
                else:
                    return o.__dict__
            for type_name, handles in by_type.items():
                for minidump_handle in handles:
                    handle_value = minidump_handle.Handle
                    handle_data = self.handles.get(handle_value, None)
                    if handle_data is not None:
                        self.debug(f"handle already added: {hex(handle_value)} = {self.handles.get(handle_value, None)}")
                        continue

                    obj: AbstractObject
                    if type_name == "Unknown":
                        obj = UnknownObject()
                    elif type_name == "File":
                        path = minidump_handle.ObjectName
                        if path is None:
                            path = "???"
                        obj = AbstractFileObject(path)
                    elif type_name == "Event":
                        # TODO: parse the ObjectInfos when available
                        event_type = EVENT_TYPE.SynchronizationEvent
                        event_signalled = False
                        obj = EventObject(event_type, event_signalled)
                    elif type_name == "Key":
                        key = minidump_handle.ObjectName
                        if key is None:
                            key = "???"
                        obj = RegistryKeyObject(key)
                    else:
                        obj = UnsupportedObject(type_name)
                    self.handles.add(handle_value, obj)

    def _setup_emulator(self, thread):
        self._setup_pebteb(thread)
        # TODO: map these using self.memory instead
        # map in codecaves (TODO: can be mapped as UC_PROT_NONE unless used)
        self._pages.commit(USER_CAVE, PAGE_SIZE, MemoryProtect.PAGE_EXECUTE_WRITECOPY)
        self._pages.write(USER_CAVE, b"\xCC" * PAGE_SIZE)
        self._pages.commit(KERNEL_CAVE, PAGE_SIZE, MemoryProtect.PAGE_EXECUTE_WRITECOPY)
        kernel_code = bytearray(b"\xCC" * (PAGE_SIZE // 2) + b"\x00" * (PAGE_SIZE // 2))
        kernel_code[IRETQ_OFFSET] = 0x48
        kernel_code[IRETD_OFFSET] = 0xCF
        self._pages.write(KERNEL_CAVE, bytes(kernel_code))

        # Set up context
        self._setup_gdt()
        if self._x64:
            self.regs.cs = windows_user_segment.cs
            self.regs.ss = windows_user_segment.ss
            self.regs.ds = windows_user_segment.ds
            self.regs.es = windows_user_segment.es
            self.regs.fs = windows_user_segment.fs
            self.regs.gs = windows_user_segment.gs
            self.regs.gs_base = self.teb

            context: minidump.CONTEXT = thread.ContextObject
            self.regs.mxcsr = context.MxCsr
            self.regs.eflags = context.EFlags & ~0x100
            self.regs.dr0 = context.Dr0
            self.regs.dr1 = context.Dr1
            self.regs.dr2 = context.Dr2
            self.regs.dr3 = context.Dr3
            self.regs.dr6 = context.Dr6
            self.regs.dr7 = context.Dr7
            self.regs.rax = context.Rax
            self.regs.rcx = context.Rcx
            self.regs.rdx = context.Rdx
            self.regs.rbx = context.Rbx
            self.regs.rsp = context.Rsp
            self.regs.rbp = context.Rbp
            self.regs.rsi = context.Rsi
            self.regs.rdi = context.Rdi
            self.regs.r8 = context.R8
            self.regs.r9 = context.R9
            self.regs.r10 = context.R10
            self.regs.r11 = context.R11
            self.regs.r12 = context.R12
            self.regs.r13 = context.R13
            self.regs.r14 = context.R14
            self.regs.r15 = context.R15
            self.regs.rip = context.Rip
        else:
            # Switch segment by execution iretq in long mode
            def push64(value):
                rsp = self.regs.rsp - 8
                self.write(rsp, struct.pack("<Q", value))
                self.regs.rsp = rsp

            self.regs.cs = windows_kernel_segment.cs
            self.regs.ss = windows_kernel_segment.ss
            self.regs.rsp = KERNEL_CAVE + (PAGE_SIZE - 0x100)
            push64(windows_wow64_segment.ss)  # SS
            push64(self.regs.esp)  # RSP
            push64(self.regs.eflags)  # EFlags
            push64(windows_wow64_segment.cs)  # CS
            push64(USER_CAVE)  # RIP
            self._uc.emu_start(begin=KERNEL_CAVE + IRETQ_OFFSET, until=USER_CAVE)
            assert self.regs.cs == windows_wow64_segment.cs
            assert self.regs.ss == windows_wow64_segment.ss
            self.regs.ds = windows_wow64_segment.ds
            self.regs.es = windows_wow64_segment.es
            self.regs.fs = windows_wow64_segment.fs
            self.regs.gs = windows_wow64_segment.gs
            self.regs.fs_base = self.teb
            self.regs.gs_base = self.teb - 2 * PAGE_SIZE

            context: minidump.WOW64_CONTEXT = thread.ContextObject
            self.regs.eflags = context.EFlags & ~0x100
            self.regs.dr0 = context.Dr0
            self.regs.dr1 = context.Dr1
            self.regs.dr2 = context.Dr2
            self.regs.dr3 = context.Dr3
            self.regs.dr6 = context.Dr6
            self.regs.dr7 = context.Dr7
            self.regs.eax = context.Eax
            self.regs.ecx = context.Ecx
            self.regs.edx = context.Edx
            self.regs.ebx = context.Ebx
            self.regs.esp = context.Esp
            self.regs.ebp = context.Ebp
            self.regs.esi = context.Esi
            self.regs.edi = context.Edi
            self.regs.eip = context.Eip

        assert self.regs.cs == context.SegCs
        assert self.regs.ss == context.SegSs
        assert self.regs.ds == context.SegDs
        assert self.regs.es == context.SegEs
        assert self.regs.fs == context.SegFs
        assert self.regs.gs == context.SegGs

        # set up hooks
        self._uc.hook_add(UC_HOOK_INSN, _hook_syscall, user_data=self, arg1=UC_X86_INS_SYSCALL)
        self._uc.hook_add(UC_HOOK_INSN, _hook_syscall, user_data=self, arg1=UC_X86_INS_SYSENTER)
        self._uc.hook_add(UC_HOOK_MEM_INVALID, _hook_mem, user_data=self)
        self._uc.hook_add(UC_HOOK_INTR, _hook_interrupt, user_data=self)
        self._uc.hook_add(UC_HOOK_INSN_INVALID, _hook_invalid, user_data=self)
        if self.trace:
            self._uc.hook_add(UC_HOOK_CODE, _hook_code, user_data=self)

    def _all_exports(self):
        exports: Dict[int, str] = {}
        for module in self.modules:
            for export in module.exports:
                if export.name:
                    name = export.name
                else:
                    name = f"#{export.ordinal}"
                exports[export.address] = f"{module.name}:{name}"
        return exports

    def _parse_module_exports(self, module):
        try:
            module_data = self.read(module.baseaddress, module.size)
        except IndexError:
            self.error(f"Failed to read module data")
            return []
        pe = PE(data=module_data, fast_load=True)
        # Hack to adjust pefile to accept in-memory modules
        for section in pe.sections:
            # Potentially interesting members: Misc_PhysicalAddress, Misc_VirtualSize, SizeOfRawData
            section.PointerToRawData = section.VirtualAddress
            section.PointerToRawData_adj = section.VirtualAddress
        # Parser exports and find the syscall indices
        pe.parse_data_directories(directories=[DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        return pe.DIRECTORY_ENTRY_EXPORT.symbols if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else []

    def _setup_modules(self):
        minidump_module: minidump.MinidumpModule
        for minidump_module in self._minidump.modules.modules:
            base = minidump_module.baseaddress
            size = minidump_module.size
            path = minidump_module.name

            # Parse the header to dump the sections from memory
            header = self.read(base, PAGE_SIZE)
            pe = PE(data=header, fast_load=True)
            image_size = pe.OPTIONAL_HEADER.SizeOfImage
            section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
            mapped_data = bytearray(header)
            mapped_data += b"\0" * (image_size - len(header))
            for section in pe.sections:
                name = section.Name.rstrip(b"\0").decode()
                mask = section_alignment - 1
                rva = (section.VirtualAddress + mask) & ~mask
                size = self.memory.align_page(section.Misc_VirtualSize)
                va = base + rva
                for page in range(va, va + size, PAGE_SIZE):
                    region = self.memory.find_commit(page)
                    if region is not None:
                        region.info = name
                try:
                    data = self.read(va, size)
                    mapped_data[rva:size] = data
                except IndexError:
                    self.error(f"Failed to read section {name} from module {path}")
            # Load the PE dumped from memory
            pe = PE(data=mapped_data, fast_load=True)
            # Hack to adjust pefile to accept in-memory modules
            for section in pe.sections:
                # Potentially interesting members: Misc_PhysicalAddress, Misc_VirtualSize, SizeOfRawData
                section.PointerToRawData = section.VirtualAddress
                section.PointerToRawData_adj = section.VirtualAddress
            self.modules.add(pe, path)

    def _setup_syscalls(self):
        # Load the ntdll module from memory
        ntdll = self.modules["ntdll.dll"]
        self.KiUserExceptionDispatcher = ntdll.find_export("KiUserExceptionDispatcher").address
        self.LdrLoadDll = ntdll.find_export("LdrLoadDll").address

        nt_syscalls = []
        for export in ntdll.exports:
            if export.name and export.name.startswith("Zw"):
                nt_syscalls.append((export.address, export.name))

        def add_syscalls(syscalls, table):
            # The index when sorting by RVA is the syscall index
            syscalls.sort()
            for index, (rva, name) in enumerate(syscalls):
                cb = syscall_functions.get(name, None)
                argcount = 0
                if cb:
                    argspec = inspect.getfullargspec(cb)
                    argcount = len(argspec.args) - 1
                table.append((name, cb, argcount))

        add_syscalls(nt_syscalls, self.syscalls)

        # Get the syscalls for win32u
        win32u = self.modules.find("win32u.dll")
        if win32u is not None:
            win32k_syscalls = []
            for export in win32u.exports:
                if export.name and export.name.startswith("Nt"):
                    win32k_syscalls.append((export.address, export.name))

            add_syscalls(win32k_syscalls, self.win32k_syscalls)


    def push(self, value):
        csp = self.regs.csp - self.ptr_size()
        self.write_ptr(csp, value)
        self.regs.csp = csp

    def pop(self):
        csp = self.regs.csp
        value = self.read_ptr(csp)
        self.regs.csp = csp + self.ptr_size()
        return value

    def ret(self, imm=0):
        return_address = self.pop()
        self.regs.csp -= imm
        return return_address

    def read(self, addr, size):
        if not isinstance(addr, int):
            addr = int(addr)
        return self._pages.read(addr, size)

    def write(self, addr, data):
        if not isinstance(addr, int):
            addr = int(addr)
        self._pages.write(addr, data)

    def call(self, addr, args: List[int] = None, regs: dict = None, count=0):
        if args is None:
            args = []
        if regs is None:
            regs = {}

        if not isinstance(addr, int):
            addr = int(addr)
        # allow passing custom registers
        for name, value in regs.items():
            self.regs.__setattr__(name, value)

        # set up arguments
        if self._x64:
            for index, value in enumerate(args):
                self.args[index] = value
        else:
            for value in reversed(args):
                self.push(value)
        # push return address
        self.push(USER_CAVE)
        # start emulation
        self.start(addr, end=USER_CAVE, count=count)
        return self.regs.cax

    def allocate(self, size, page_align=False):
        if not self._allocate_ptr:
            self._allocate_base = self.memory.find_free(self._allocate_size)
            assert self._allocate_base is not None, "Failed to find free memory"
            self.memory.reserve(
                start=self._allocate_base,
                size=self._allocate_size,
                protect=MemoryProtect.PAGE_EXECUTE_READWRITE,
                memory_type=MemoryType.MEM_PRIVATE,
                info="allocated region"
            )
            self._allocate_ptr = self._allocate_base

        if page_align:
            self._allocate_ptr = round_to_pages(self._allocate_ptr)
            size = round_to_pages(size)

        if self._allocate_ptr + size > self._allocate_base + self._allocate_size:
            raise Exception("not enough room to allocate!")

        ptr = self._allocate_ptr
        self._allocate_ptr += size
        self.memory.commit(self.memory.align_page(ptr), self.memory.align_page(size))
        return ptr

    def set_exception_hook(self, exception_hook: Optional[Callable[[ExceptionInfo], Optional[int]]]):
        previous_hook = self._exception_hook
        self._exception_hook = exception_hook
        return previous_hook

    def handle_exception(self):
        assert not self._exception._handling
        self._exception._handling = True

        if self._exception_hook is not None:
            hook_result = self._exception_hook(self._exception)
            if self.stopped:
                return None
            if hook_result is not None:
                # Clear the pending exception
                self._last_exception = self._exception
                self._exception = UnicornExceptionInfo()
                return hook_result

        if self._exception.type == ExceptionType.ContextSwitch:
            self.info(f"context switch, cip: {hex(self.regs.cip)}")
            # Clear the pending exception
            self._last_exception = self._exception
            self._exception = UnicornExceptionInfo()
            # NOTE: the context has already been restored using context_restore in the caller
            return self.regs.cip

        self.info(f"handling exception...")

        if self._x64:
            # Stack layout (x64):
            # CONTEXT: 0x4d0 bytes (not all fields are overwritten)
            # CONTEXT_EX: 0x18 bytes (accessed by RtlpSanitizeContext)
            # Alignment: 0x8 bytes (not overwritten by KiUserExceptionDispatcher)
            # EXCEPTION_RECORD: 0x98 bytes
            # Unknown: 0x198 bytes (JustMagic: should be _MACHINE_FRAME?)
            # 0x4f0 bytes sizeof(CONTEXT) + 0x20 unclear
            """ JustMagic:
rsp in KiUserExceptionDispatcher:
      CONTEXT          @ rsp + 0   : 4d0
      CONTEXT_EX       @ rsp + 4d0 : 18
      alignment        @ rsp + 4e8 : 8
      EXCEPTION_RECORD @ rsp + 4f0 : 98
      alignment        @ rsp + 588 : 8
      MACHINE_FRAME    @ rsp + 590 : 28                       | alignas(16) from RSP in exception / xstate
      alignment        @ rsp + 5b8 : 8
      xstate           @ rsp + 5c0 : CONTEXT_EX.Xstate.Length | alignas(64) from RSP in exception
            """
            allocation_size = 0x720
            context_flags = 0x10005F
            record_type = EXCEPTION_RECORD64
            context_type = CONTEXT
        else:
            # Stack layout (x86):
            # EXCEPTION_RECORD*: 0x4 bytes
            # CONTEXT*: 0x4 bytes
            # EXCEPTION_RECORD: 0x50
            # CONTEXT: 0x2cc
            # CONTEXT_EX: 0x18
            # Unknown: 0x17C bytes
            allocation_size = 0x4b8
            context_flags = 0x1007F
            record_type = EXCEPTION_RECORD32
            context_type = WOW64_CONTEXT

        csp = self.regs.csp - allocation_size
        self.write(csp, allocation_size * b"\x69")  # fill stuff with 0x69 for debugging
        self.info(f"old csp: {hex(self.regs.csp)}, new csp: {hex(csp)}")
        context_size = ctypes.sizeof(context_type)
        context = context_type.from_buffer(self.read(csp, context_size))
        context.ContextFlags = context_flags
        context.from_regs(self.regs)
        context_ex = CONTEXT_EX()
        context_ex.All.Offset = -context_size & 0xFFFFFFFF
        context_ex.All.Length = allocation_size if self._x64 else 0x42C  # TODO: why this value?
        context_ex.Legacy.Offset = -context_size & 0xFFFFFFFF
        context_ex.Legacy.Length = context_size
        context_ex.XState.Offset = 0xF0 if self._x64 else 0x20
        context_ex.XState.Length = 0x160 if self._x64 else 0x140
        record = record_type()
        alignment_violations = [MemoryViolation.ReadUnaligned, MemoryViolation.WriteUnaligned, MemoryViolation.ExecuteUnaligned]
        if self._exception.type == ExceptionType.Memory and self._exception.memory_violation not in alignment_violations:
            record.ExceptionCode = STATUS_ACCESS_VIOLATION
            record.ExceptionFlags = 0
            record.ExceptionAddress = self.regs.cip
            record.NumberParameters = 2
            types = {
                MemoryViolation.ReadUnmapped: EXCEPTION_READ_FAULT,
                MemoryViolation.WriteUnmapped: EXCEPTION_WRITE_FAULT,
                MemoryViolation.ExecuteUnmapped: EXCEPTION_READ_FAULT,
                MemoryViolation.ReadProtect: EXCEPTION_READ_FAULT,
                MemoryViolation.WriteProtect: EXCEPTION_WRITE_FAULT,
                MemoryViolation.ExecuteProtect: EXCEPTION_EXECUTE_FAULT,
            }
            record.ExceptionInformation[0] = types[self._exception.memory_violation]
            record.ExceptionInformation[1] = self._exception.memory_address
        elif self._exception.type == ExceptionType.Interrupt and self._exception.interrupt_number == 3:
            if self._x64:
                context.Rip -= 1  # TODO: long int3 and prefixes
                record.ExceptionCode = 0x80000003
                record.ExceptionFlags = 0
                record.ExceptionAddress = context.Rip
                record.NumberParameters = 1
            else:
                context.Eip -= 1  # TODO: long int3 and prefixes
                record.ExceptionCode = 0x80000003
                record.ExceptionFlags = 0
                record.ExceptionAddress = context.Eip
                record.NumberParameters = 1
        else:
            raise NotImplementedError(f"{self._exception}")  # TODO: implement

        # Clear the pending exception
        self._last_exception = self._exception
        self._exception = UnicornExceptionInfo()

        def write_stack(cur_ptr: int, data: bytes):
            self.write(cur_ptr, data)
            return cur_ptr + len(data)

        ptr = csp
        if self._x64:
            ptr = write_stack(ptr, bytes(context))
            ptr = write_stack(ptr, bytes(context_ex))
            ptr += 8  # alignment TODO: check if aligned?
            ptr = write_stack(ptr, bytes(record))
            ptr += 8  # not set
            ptr = write_stack(ptr, struct.pack("<Q", record.ExceptionAddress))
            ptr += 16  # not set
            ptr = write_stack(ptr, struct.pack("<Q", context.Rsp))
            ptr += 16  # not set
            ptr = write_stack(ptr, struct.pack("<QIIQQQQQQ", 0, 4, 8, 0, 0, 0, 0, 0, 0))
        else:
            ptr += 4 * 2
            self.write_ulong(csp, ptr)
            ptr = write_stack(ptr, bytes(record))
            self.write_ulong(csp + 4, ptr)
            ptr = write_stack(ptr, bytes(context))
            ptr = write_stack(ptr, bytes(context_ex))
        self.regs.csp = csp
        return self.KiUserExceptionDispatcher

    def start(self, begin, end=0xffffffffffffffff, count=0) -> None:
        # Clear stop state
        self.stopped = False
        self.kill_exception = None
        self.exit_code = None
        # Clear exceptions before starting
        self._exception = UnicornExceptionInfo()
        emu_begin = begin
        emu_until = end
        emu_count = count
        while not self.stopped:
            try:
                if self._exception.type != ExceptionType.NoException:
                    if self._exception.final:
                        # Restore the context (unicorn might mess with it before stopping)
                        if self._exception.context is not None:
                            self._uc.context_restore(self._exception.context)

                        if self._exception.type == ExceptionType.Terminate:
                            if self.exit_code is not None:
                                self.info(f"exit code: {hex(self.exit_code)}")
                            break

                        try:
                            emu_begin = self.handle_exception()
                            if self.stopped:
                                break
                        except Exception:
                            traceback.print_exc()
                            self.error(f"exception during exception handling (stack overflow?)")
                            break
                        emu_until = end
                        emu_count = 0
                    else:
                        # If this happens there was an error restarting simulation
                        assert self._exception.step_count == 0

                        # Hook should be installed at this point
                        assert self._exception.code_hook_h is not None

                        # Restore the context (unicorn might mess with it before stopping)
                        assert self._exception.context is not None
                        self._uc.context_restore(self._exception.context)

                        # Restart emulation
                        self.info(f"restarting emulation to handle exception...")
                        emu_begin = self.regs.cip
                        emu_until = 0xffffffffffffffff
                        emu_count = self._exception.tb_icount + 1

                self.info(f"emu_start({hex(emu_begin)}, {hex(emu_until)}, {emu_count})")
                self._uc.emu_start(emu_begin, until=emu_until, count=emu_count)
                self.info(f'emulation finished, cip = {hex(self.regs.cip)}')
                if self.exit_code is not None:
                    self.info(f"exit code: {hex(self.exit_code)}")
                break
            except UcError as err:
                if self.kill_exception is not None and type(self.kill_exception) is not UcError:
                    raise self.kill_exception from None
                if self._exception.type != ExceptionType.NoException:
                    # Handle the exception outside of the except handler
                    continue
                else:
                    self.error(f'error: {err}, cip = {hex(self.regs.cip)}')
                    traceback.print_exc()
                break

    def stop(self, exit_code=None) -> None:
        try:
            self.exit_code = None
            if exit_code is not None:
                self.exit_code = int(exit_code)
        except Exception:
            traceback.print_exc()
            self.error("Invalid type passed to exit_code!")
        self.stopped = True
        self._uc.emu_stop()

    def raise_kill(self, exc=None):
        # HACK: You need to use this to exit from hooks (although it might not always work)
        self.regs.cip = FORCE_KILL_ADDR
        self.stop()
        if exc is None:
            exc = Exception()
        self.kill_exception = exc
        return exc

    def NtCurrentProcess(self):
        return 0xFFFFFFFFFFFFFFFF if self._x64 else 0xFFFFFFFF

    def NtCurrentThread(self):
        return 0xFFFFFFFFFFFFFFFE if self._x64 else 0xFFFFFFFE

    def map_module(self, file_data: bytes, file_path: str = "", requested_base: int = 0, resolve_imports=True):
        if not file_path:
            file_path = "<unnamed>"
        print(f"Mapping module {file_path}")
        pe = PE(name=None, data=bytearray(file_data))
        image_size = pe.OPTIONAL_HEADER.SizeOfImage
        section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
        assert section_alignment == 0x1000, f"Unsupported section alignment {hex(section_alignment)}"
        bits = 64 if pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS else 32
        assert bits == 8 * self.ptr_size(), f"PE architecture mismatch"

        if requested_base == 0:
            image_base = self.memory.find_free(image_size)
        else:
            image_base = requested_base
        self.memory.reserve(image_base, image_size, MemoryProtect.PAGE_EXECUTE_WRITECOPY, MemoryType.MEM_MAPPED)

        # Fix relocations, saves to pe.__data__ buffer
        pe.relocate_image(image_base)
        # NOTE: workaround for a bug in pefile where it doesn't set the image base if there are no relocations
        pe.OPTIONAL_HEADER.ImageBase = image_base

        # https://vtopan.wordpress.com/2019/04/12/patching-resolving-imports-in-a-pe-file-python-pefile/
        # manually resolve imports
        if resolve_imports and hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            ordinal_flag = 2 ** (bits - 1)
            for iid in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = iid.dll.decode("utf-8").lower()
                dll = self.modules.find(dll_name)
                assert dll is not None, f"{dll_name} is not loaded"
                self.info(f"resolving imports for {dll_name}")
                ilt_rva = iid.struct.OriginalFirstThunk
                ilt = pe.get_import_table(ilt_rva)
                iat_rva = iid.struct.FirstThunk
                iat = pe.get_import_table(iat_rva)
                assert iat is not None, "iat is empty"
                assert ilt is not None, "ilt is empty"
                for idx in range(len(ilt)):
                    hint_rva = ilt[idx].AddressOfData
                    assert hint_rva is not None, "hint_rva is 0"
                    if hint_rva & ordinal_flag:
                        ordinal = f"#{hint_rva & 0xffff}"
                        export = self.modules.resolve_export(dll.name, ordinal)
                        assert export is not None, f"Ordinal #{ordinal} not in {dll_name}"
                        imp_va = export.address
                        self.info(f"\t#{ordinal} = {hex(imp_va)}")
                    else:
                        hint = pe.get_word_from_data(pe.get_data(hint_rva, 2), 0)
                        func_name = pe.get_string_at_rva(ilt[idx].AddressOfData + 2, MAX_IMPORT_NAME_LENGTH)
                        func_name = func_name.decode("utf-8")
                        export = self.modules.resolve_export(dll.name, func_name)
                        assert export is not None, f"Export {func_name} not in {dll_name}"
                        imp_va = export.address
                        self.info(f"\t{func_name} = {hex(imp_va)}")
                    file_offset = iat[idx].get_field_absolute_offset("AddressOfData")
                    if bits == 64:
                        pe.__data__[file_offset:file_offset + 8] = struct.pack("<Q", imp_va)
                    else:
                        pe.__data__[file_offset:file_offset + 4] = struct.pack("<L", imp_va)

        # HACK: apply the change to the ImageBase to the header bytes
        file_offset = pe.OPTIONAL_HEADER.get_field_absolute_offset("ImageBase")
        if bits == 64:
            pe.__data__[file_offset:file_offset + 8] = struct.pack("<Q", image_base)
        else:
            pe.__data__[file_offset:file_offset + 4] = struct.pack("<L", image_base)
        pe.header = pe.__data__[:len(pe.header)]
        # TODO: map the header properly (figure out how the system assigns the size)
        header_size = pe.sections[0].VirtualAddress_adj
        print(f"Mapping header {hex(image_base)}[{hex(header_size)}]")
        self.memory.commit(image_base, header_size, MemoryProtect.PAGE_READONLY)
        self.write(image_base, bytes(pe.header))

        for section in pe.sections:
            name = section.Name.rstrip(b"\0")
            mask = section_alignment - 1
            rva = (section.VirtualAddress_adj + mask) & ~mask
            va = image_base + rva
            size = self.memory.align_page(section.Misc_VirtualSize)
            flags = section.Characteristics
            data = bytes(section.get_data())
            assert flags & IMAGE_SCN_MEM_SHARED == 0, "Shared sections are not supported"
            assert flags & IMAGE_SCN_MEM_READ != 0, "Non-readable sections are not supported"
            execute = flags & IMAGE_SCN_MEM_EXECUTE
            write = flags & IMAGE_SCN_MEM_WRITE
            protect = MemoryProtect.PAGE_READONLY
            if write:
                protect = MemoryProtect.PAGE_READWRITE
            if execute:
                protect = MemoryProtect(protect.value << 4)
            print(f"Mapping section '{name.decode()}' {hex(rva)}[{hex(rva)}] -> {hex(va)} as {protect}")
            self.memory.commit(va, size, protect)
            self.write(va, data)

        # Add the module to the module manager
        return self.modules.add(pe, file_path)

    def load_dll(self, file_name: str, file_data: bytes):
        self.handles.map_file("\\??\\" + file_name, FileObject(file_name, file_data))
        argument_ptr = self.allocate(PAGE_SIZE)
        utf16 = file_name.encode("utf-16-le")
        if self._x64:
            argument_data = struct.pack("<IIQHHIQ", 0, 0, 0, len(utf16), len(utf16) + 2, 0, argument_ptr + 32)
            argument_data += utf16
            argument_data += b"\0"
            search_path = argument_ptr + len(argument_data)
            argument_data += b"Z:\\"
            image_type = argument_ptr
            image_base_address = image_type + 8
            image_file_name = image_base_address + 8
        else:
            assert False # TODO
        self.write(argument_ptr, argument_data)

        print(f"LdrLoadDll({file_name})")
        status = self.call(self.LdrLoadDll, [1, image_type, image_file_name, image_base_address])
        print(f"status = {hex(status)}")
        return self.read_ptr(image_base_address)

def _hook_code_exception(uc: Uc, address, size, dp: Dumpulator):
    try:
        dp.info(f"exception step: {hex(address)}[{size}]")
        ex = dp._exception
        ex.step_count += 1
        if ex.step_count >= ex.tb_icount:
            raise Exception("Stepped past the basic block without reaching exception")
    except UcError as err:
        dp.error(f"Exception during unicorn hook, please report this as a bug")
        raise err

def _hook_mem(uc: Uc, access, address, size, value, dp: Dumpulator):
    if dp._pages.handle_lazy_page(address, min(size, PAGE_SIZE)):
        dp.debug(f"committed lazy page {hex(address)}[{hex(size)}] (cip: {hex(dp.regs.cip)})")
        return True

    fetch_accesses = [UC_MEM_FETCH, UC_MEM_FETCH_PROT, UC_MEM_FETCH_UNMAPPED]
    if dp.stopped and access == UC_MEM_FETCH_UNMAPPED and FORCE_KILL_ADDR - 0x10 <= address <= FORCE_KILL_ADDR + 0x10:
        dp.error(f"force exit fetch of {hex(address)}[{hex(size)}]")
        return False
    if dp._exception.final and access in fetch_accesses:
        dp.info(f"fetch from {hex(address)}[{size}] already reported")
        return False
    # TODO: figure out why when you start executing at 0 this callback is triggered more than once
    try:
        violation = {
            UC_MEM_READ_UNMAPPED: MemoryViolation.ReadUnmapped,
            UC_MEM_WRITE_UNMAPPED: MemoryViolation.WriteUnmapped,
            UC_MEM_FETCH_UNMAPPED: MemoryViolation.ExecuteUnmapped,
            UC_MEM_READ_PROT: MemoryViolation.ReadProtect,
            UC_MEM_WRITE_PROT: MemoryViolation.WriteProtect,
            UC_MEM_FETCH_PROT: MemoryViolation.ExecuteProtect,
        }.get(access, MemoryViolation.Unknown)
        assert violation != MemoryViolation.Unknown, f"Unexpected memory access {access}"
        # Extract exception information
        exception = UnicornExceptionInfo()
        exception.type = ExceptionType.Memory
        exception.memory_violation = violation
        exception.memory_address = address
        exception.memory_size = size
        exception.memory_value = value
        exception.context = uc.context_save()
        if access not in fetch_accesses:
            tb = uc.ctl_request_cache(dp.regs.cip)
            exception.tb_start = tb.pc
            exception.tb_size = tb.size
            exception.tb_icount = tb.icount

        # Print exception info
        final = dp.trace or dp._exception.code_hook_h is not None
        info = "final" if final else "initial"
        if access == UC_MEM_READ_UNMAPPED:
            dp.error(f"{info} unmapped read from {hex(address)}[{hex(size)}], cip = {hex(dp.regs.cip)}, exception: {exception}")
        elif access == UC_MEM_WRITE_UNMAPPED:
            dp.error(f"{info} unmapped write to {hex(address)}[{hex(size)}] = {hex(value)}, cip = {hex(dp.regs.cip)}")
        elif access == UC_MEM_FETCH_UNMAPPED:
            dp.error(f"{info} unmapped fetch of {hex(address)}[{hex(size)}], cip = {hex(dp.regs.rip)}, cs = {hex(dp.regs.cs)}")
        else:
            names = {
                UC_MEM_READ: "UC_MEM_READ", # Memory is read from
                UC_MEM_WRITE: "UC_MEM_WRITE", # Memory is written to
                UC_MEM_FETCH: "UC_MEM_FETCH", # Memory is fetched
                UC_MEM_READ_UNMAPPED: "UC_MEM_READ_UNMAPPED", # Unmapped memory is read from
                UC_MEM_WRITE_UNMAPPED: "UC_MEM_WRITE_UNMAPPED", # Unmapped memory is written to
                UC_MEM_FETCH_UNMAPPED: "UC_MEM_FETCH_UNMAPPED", # Unmapped memory is fetched
                UC_MEM_WRITE_PROT: "UC_MEM_WRITE_PROT", # Write to write protected, but mapped, memory
                UC_MEM_READ_PROT: "UC_MEM_READ_PROT", # Read from read protected, but mapped, memory
                UC_MEM_FETCH_PROT: "UC_MEM_FETCH_PROT", # Fetch from non-executable, but mapped, memory
                UC_MEM_READ_AFTER: "UC_MEM_READ_AFTER", # Memory is read from (successful access)
            }
            dp.error(f"{info} unsupported access {names.get(access, str(access))} of {hex(address)}[{hex(size)}] = {hex(value)}, cip = {hex(dp.regs.cip)}")

        if final:
            # Make sure this is the same exception we expect
            if not dp.trace:
                assert violation == dp._exception.memory_violation
                assert address == dp._exception.memory_address
                assert size == dp._exception.memory_size
                assert value == dp._exception.memory_value

                # Delete the code hook
                uc.hook_del(dp._exception.code_hook_h)
                dp._exception.code_hook_h = None

            # At this point we know for sure the context is correct so we can report the exception
            dp._exception = exception
            dp._exception.final = True

            # Stop emulation (we resume it on KiUserExceptionDispatcher later)
            dp._uc.emu_stop()
            return False

        # There should not be an exception active
        assert dp._exception.type == ExceptionType.NoException

        # Remove the translation block cache for this block
        # Without doing this single stepping the block won't work
        if exception.tb_start != 0:
            uc.ctl_remove_cache(exception.tb_start, exception.tb_start + exception.tb_size)

        # Install the code hook to single step the basic block again.
        # This will prevent translation block caching and give us the correct cip
        exception.code_hook_h = uc.hook_add(UC_HOOK_CODE, _hook_code_exception, user_data=dp)

        # Store the exception info
        dp._exception = exception

        # Stop emulation (we resume execution later)
        dp._uc.emu_stop()
        return False
    except AssertionError as err:
        traceback.print_exc()
        raise err
    except UcError as err:
        dp.error(f"Exception during unicorn hook, please report this as a bug")
        raise err
    except Exception as err:
        raise err

def _get_regs(instr, include_write=False):
    regs = OrderedDict()
    operands = instr.operands
    if instr.id != X86_INS_NOP:
        for i in range(0, len(operands)):
            op = operands[i]
            if op.type == CS_OP_REG:
                is_write_op = (i == 0 and instr.id in [X86_INS_MOV, X86_INS_MOVZX, X86_INS_LEA])
                if not is_write_op and not include_write:
                    regs[instr.reg_name(op.value.reg)] = None
            elif op.type == CS_OP_MEM:
                if op.value.mem.base not in [0, X86_REG_RIP]:
                    regs[instr.reg_name(op.value.mem.base)] = None
                if op.value.mem.index not in [0, X86_REG_RIP]:
                    regs[instr.reg_name(op.value.mem.index)] = None
        for reg in instr.regs_read:
            regs[instr.reg_name(reg)] = None
        if include_write:
            for reg in instr.regs_write:
                regs[instr.reg_name(reg)] = None
    return regs

def _hook_code(uc: Uc, address, size, dp: Dumpulator):
    try:
        code = b""
        try:
            code = dp.read(address, min(size, 15))
            instr = next(dp.cs.disasm(code, address, 1))
        except StopIteration:
            instr = None  # Unsupported instruction
        except IndexError:
            instr = None  # Likely invalid memory
        address_name = dp.exports.get(address, "")

        module = ""
        if dp.last_module and address in dp.last_module:
            # same module again
            pass
        else:
            # new module
            dp.last_module = dp.modules.find(address)
            if dp.last_module:
                module = dp.last_module.name

        if address_name:
            address_name = " " + address_name
        elif module:
            address_name = " " + module

        line = f"{hex(address)}{address_name}|"
        if instr is not None:
            line += instr.mnemonic
            if instr.op_str:
                line += " "
                line += instr.op_str
            for reg in _get_regs(instr):
                line += f"|{reg}={hex(dp.regs.__getattr__(reg))}"
            if instr.mnemonic == "call":
                # print return address
                ret_address = address + instr.size
                line += f"|return_address={hex(ret_address)}"
            elif instr.mnemonic in {"syscall", "sysenter"}:
                line += f"|sequence_id=[{dp.sequence_id}]"
        else:
            line += f"??? (code: {code.hex()}, size: {hex(size)})"
        line += "\n"
        dp.trace.write(line)
    except (KeyboardInterrupt, SystemExit) as e:
        dp.stop()
        raise e

def _unicode_string_to_string(dp: Dumpulator, arg: P[UNICODE_STRING]):
    try:
        return arg[0].read_str()
    except IndexError:
        return None

def _object_attributes_to_string(dp: Dumpulator, arg: P[OBJECT_ATTRIBUTES]):
    try:
        return arg[0].ObjectName[0].read_str()
    except IndexError:
        pass
    return None

def _arg_to_string(dp: Dumpulator, arg):
    if isinstance(arg, Enum):
        return arg.name
    elif isinstance(arg, HANDLE):
        str = hex(arg)
        hstr = None
        if arg == dp.NtCurrentProcess():
            hstr = "NtCurrentProcess()"
        elif arg == dp.NtCurrentThread():
            hstr = "NtCurrentThread()"
        elif dp.handles.valid(arg):
            hstr = f"{dp.handles.get(arg, None)}"
        if hstr is not None:
            str += f" /* {hstr} */"
        return str
    elif P.is_ptr(arg):
        str = hex(arg.ptr)
        tstr = None
        if arg.type is OBJECT_ATTRIBUTES:
            tstr = _object_attributes_to_string(dp, arg)
        elif arg.type is UNICODE_STRING:
            tstr = f"\"{_unicode_string_to_string(dp, arg)}\""
        if tstr is not None:
            str += f" /* {tstr} */"
        return str
    elif isinstance(arg, int):
        return hex(arg)
    raise NotImplemented()

def _arg_type_string(arg):
    if P.is_ptr(arg) and arg.type is not None:
        return arg.type.__name__ + "*"
    return type(arg).__name__

def _hook_interrupt(uc: Uc, number, dp: Dumpulator):
    if dp.trace:
        dp.trace.flush()
    try:
        # Extract exception information
        exception = UnicornExceptionInfo()
        exception.type = ExceptionType.Interrupt
        exception.interrupt_number = number
        exception.context = uc.context_save()
        # TODO: this might crash if cip is not valid memory
        tb = uc.ctl_request_cache(dp.regs.cip)
        exception.tb_start = tb.pc
        exception.tb_size = tb.size
        exception.tb_icount = tb.icount

        # Print exception info
        if number < len(interrupt_names):
            description = interrupt_names[number]
        else:
            description = f"IRQ {number - 32}"
        dp.error(f"interrupt {number} ({description}), cip = {hex(dp.regs.cip)}, cs = {hex(dp.regs.cs)}")

        # There should not be an exception active
        assert dp._exception.type == ExceptionType.NoException

        # At this point we know for sure the context is correct so we can report the exception
        dp._exception = exception
        dp._exception.final = True
    except AssertionError as err:
        traceback.print_exc()
        raise err
    except UcError as err:
        dp.error(f"Exception during unicorn hook, please report this as a bug")
        raise err
    except Exception as err:
        raise err

    # Stop emulation (we resume it on KiUserExceptionDispatcher later)
    raise UcError(UC_ERR_EXCEPTION)

def _hook_syscall(uc: Uc, dp: Dumpulator):
    # Flush the trace for easier debugging
    if dp.trace is not None:
        dp.trace.flush()

    # Extract the table and function number from eax
    service_number = dp.regs.cax & 0xffff
    table_number = (service_number >> 12) & 0xf  # 0: ntoskrnl, 1: win32k
    function_index = service_number & 0xfff
    if table_number == 0:
        table = dp.syscalls
        table_prefix = ""
    elif table_number == 1:
        table = dp.win32k_syscalls
        table_prefix = "win32k "
    else:
        table = []
        table_prefix = f"unknown:{table_number} "

    if function_index < len(table):
        name, syscall_impl, argcount = table[function_index]
        if syscall_impl:
            argspec = inspect.getfullargspec(syscall_impl)
            args = []

            def syscall_arg(index):
                # There is an extra call that adds a return address to the stack
                if dp.wow64:
                    index += 1
                if index == 0 and dp.ptr_size() == 8:
                    return dp.regs.r10
                return dp.args[index]

            dp.info(f"[{dp.sequence_id}] {table_prefix}syscall: {name}( /* index: {hex(service_number)} */")
            for i in range(0, argcount):
                argname = argspec.args[1 + i]
                argtype = argspec.annotations[argname]
                # Extract the type information from the annotation
                # Reference: https://github.com/python/cpython/issues/89543
                # It looks like the python designers did an oopsie, so we're going
                # the fully-undocumented route.
                sal = None
                if "Annotated" in type(argtype).__name__:
                    sal, = argtype.__metadata__
                    argtype = argtype.__origin__

                if sal is None:
                    sal_pretty = ""
                else:
                    sal_pretty = str(sal) + " "

                argvalue = syscall_arg(i)
                if P.is_ptr(argtype):
                    argvalue = argtype(dp, argvalue)
                elif issubclass(argtype, Enum):
                    try:
                        argvalue = argtype(argvalue & 0xFFFFFFFF)
                    except KeyError as x:
                        raise Exception(f"Unknown enum value {argvalue} for {type(argtype)}") from None
                else:
                    argvalue = argtype(argvalue)
                args.append(argvalue)

                comma = ","
                if i + 1 == argcount:
                    comma = ""

                dp.info(f"    {sal_pretty}{_arg_type_string(argvalue)} {argname} = {_arg_to_string(dp, argvalue)}{comma}")
            dp.info(")")
            try:
                status = syscall_impl(dp, *args)
                if isinstance(status, ExceptionInfo):
                    print("context switch, stopping emulation")
                    dp._exception = status
                    raise UcError(UC_ERR_EXCEPTION)
                else:
                    dp.info(f"status = {hex(status)}")
                    dp.regs.cax = status
                    if dp.x64:
                        dp.regs.rcx = dp.regs.cip + 2
                        dp.regs.r11 = dp.regs.eflags
                    else:
                        # HACK: there is a bug in unicorn that doesn't increment EIP
                        dp.regs.eip += 2
            except UcError as err:
                raise err
            except Exception as exc:
                dp.error(f"Exception thrown during syscall implementation, stopping emulation!")
                raise dp.raise_kill(exc) from None
            finally:
                dp.sequence_id += 1
        else:
            raise dp.raise_kill(NotImplementedError(f"{table_prefix}syscall {hex(service_number)} -> {name} not implemented!")) from None
    else:
        raise dp.raise_kill(IndexError(f"{table_prefix}syscall {hex(service_number)} (index: {hex(function_index)}) out of range")) from None

def _emulate_unsupported_instruction(dp: Dumpulator, instr: CsInsn):
    if instr.id == X86_INS_RDRAND:
        op: X86Op = instr.operands[0]
        regname = instr.reg_name(op.reg)
        if dp.x64 and op.size * 8 == 32:
            regname = "r" + regname[1:]
        print(f"emulated rdrand {regname}:{op.size * 8}, cip = {hex(instr.address)}+{instr.size}")
        dp.regs[regname] = 42  # TODO: PRNG based on dmp hash
        dp.regs.cip += instr.size
    else:
        # Unsupported instruction
        return False
    # Resume execution
    return True

def _hook_invalid(uc: Uc, dp: Dumpulator):
    address = dp.regs.cip
    if dp.trace:
        dp.trace.flush()
    # HACK: unicorn cannot gracefully exit in all contexts
    if dp.stopped:
        dp.error(f"terminating emulation...")
        return False
    dp.error(f"invalid instruction at {hex(address)}")
    try:
        code = dp.read(address, 15)
        instr = next(dp.cs.disasm(code, address, 1))
        if _emulate_unsupported_instruction(dp, instr):
            # Resume execution with a context switch
            assert dp._exception.type == ExceptionType.NoException
            exception = UnicornExceptionInfo()
            exception.type = ExceptionType.ContextSwitch
            exception.final = True
            dp._exception = exception
            return False  # NOTE: returning True would stop emulation
    except StopIteration:
        pass  # Unsupported instruction
    except IndexError:
        pass  # Invalid memory access (NOTE: this should not be possible actually)
    raise NotImplementedError("TODO: throw invalid instruction exception")
