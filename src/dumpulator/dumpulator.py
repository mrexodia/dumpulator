import ctypes
import struct
import sys
import traceback
from enum import Enum
from typing import List, Union, NamedTuple
import inspect
from collections import OrderedDict

import minidump.minidumpfile as minidump
from unicorn import *
from unicorn.x86_const import *
from pefile import *

from .handles import HandleManager, FileObject
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

class ExceptionInfo:
    def __init__(self):
        self.type = ExceptionType.NoException
        self.memory_access = 0
        self.memory_address = 0
        self.memory_size = 0
        self.memory_value = 0
        self.interrupt_number = 0
        self.code_hook_h: Optional[int] = None  # TODO: should be unicorn.uc_hook_h, but type error
        self.context: Optional[unicorn.UcContext] = None
        self.tb_start = 0
        self.tb_size = 0
        self.tb_icount = 0
        self.step_count = 0
        self.final = False
        self.handling = False

    def __str__(self):
        return f"{self.type}, ({hex(self.tb_start)}, {hex(self.tb_size)}, {self.tb_icount})"

class UnicornPageManager(PageManager):
    def __init__(self, uc: Uc):
        self._uc = uc

    def commit(self, addr: int, size: int, protect: MemoryProtect) -> None:
        perms = map_unicorn_perms(protect)
        self._uc.mem_map(addr, size, perms)

    def decommit(self, addr: int, size: int) -> None:
        self._uc.mem_unmap(addr, size)

    def protect(self, addr: int, size: int, protect: MemoryProtect) -> None:
        self._uc.mem_protect(addr, size, map_unicorn_perms(protect))

class Dumpulator(Architecture):
    def __init__(self, minidump_file, *, trace=False, quiet=False, thread_id=None):
        self._quiet = quiet
        self._debug = False

        # Load the minidump
        self._minidump = minidump.MinidumpFile.parse(minidump_file)
        if thread_id is None and self._minidump.exception is not None:
            thread_id = self._minidump.exception.exception_records[0].ThreadId
        if thread_id is None:
            thread = self._minidump.threads.threads[0]
        else:
            thread = self._find_thread(thread_id)

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
        self.args = Arguments(self._uc, self.regs, self._x64)
        self.memory = MemoryManager(UnicornPageManager(self._uc))
        self.modules = ModuleManager(self.memory)
        self._allocate_base = None
        self._allocate_size = 1024 * 1024 * 10  # NOTE: 10 megs
        self._allocate_ptr = None
        self._setup_memory()
        self._setup_modules()
        self._setup_emulator(thread)
        self.kill_me = None
        self.exit_code = None
        self.syscalls = []
        self._setup_syscalls()
        self.exports = self._all_exports()
        self.handles = HandleManager()
        self.exception = ExceptionInfo()
        self.last_exception: Optional[ExceptionInfo] = None
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
                if isinstance(region.info, Module):
                    module: Module = region.info
                    entry[4] = f" {module.name}[{hex(module.size)}]"
                elif region.info:
                    entry[4] = str(region.info)
            table.append(entry)
        print(format_table(table))

    def _find_thread(self, thread_id):
        for i in range(0, len(self._minidump.threads.threads)):
            thread = self._minidump.threads.threads[i]
            if thread.ThreadId == thread_id:
                return thread
        raise Exception(f"Thread 0x{thread_id:x} ({thread_id}) not found!")

    def debug(self, message: str):
        if self._debug:
            print(message)

    def info(self, message: str):
        if not self._quiet:
            print(message)

    def error(self, message: str):
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
        self._uc.mem_map(TSS_BASE, PAGE_SIZE, UC_PROT_READ | UC_PROT_WRITE)

        self._uc.mem_map(GDT_BASE, PAGE_SIZE, UC_PROT_READ | UC_PROT_WRITE)
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
            emu_addr = info.BaseAddress & self.addr_mask
            if info.State == minidump.MemoryState.MEM_FREE:
                continue
            reserve_protect = MemoryProtect(info.AllocationProtect)
            reserve_type = MemoryType(info.Type.value)
            self.debug(f" reserved: {hex(reserve_addr)}, size: {hex(reserve_size)}, protect: {reserve_protect}, type: {reserve_type}")
            self.memory.reserve(reserve_addr, reserve_size, reserve_protect, reserve_type)
            for info in region:
                emu_addr = info.BaseAddress & self.addr_mask
                if info.State == minidump.MemoryState.MEM_COMMIT:
                    protect = reserve_protect if info.Protect is None else MemoryProtect(info.Protect.value)
                    self.debug(f"committed: {hex(emu_addr)}, size: {hex(info.RegionSize)}, protect: {protect}")
                    self.memory.commit(info.BaseAddress, info.RegionSize, protect)
        self.memory._granularity = 0x10000

        memory = self._minidump.get_reader().get_buffered_reader()
        seg: minidump.MinidumpMemorySegment
        for seg in self._minidump.memory_segments_64.memory_segments:
            emu_addr = seg.start_virtual_address & self.addr_mask
            self.debug(f"initialize base: 0x{emu_addr:x}, size: 0x{seg.size:x}")
            memory.move(seg.start_virtual_address)
            assert memory.current_position == seg.start_virtual_address
            data = memory.read(seg.size)
            self._uc.mem_write(emu_addr, data)

    def _setup_emulator(self, thread):
        # TODO: map these using self.memory instead
        # map in codecaves (TODO: can be mapped as UC_PROT_NONE unless used)
        self._uc.mem_map(USER_CAVE, PAGE_SIZE)
        self._uc.mem_write(USER_CAVE, b"\xCC" * PAGE_SIZE)
        self._uc.mem_map(KERNEL_CAVE, PAGE_SIZE)
        kernel_code = bytearray(b"\xCC" * (PAGE_SIZE // 2) + b"\x00" * (PAGE_SIZE // 2))
        kernel_code[IRETQ_OFFSET] = 0x48
        kernel_code[IRETD_OFFSET] = 0xCF
        self._uc.mem_write(KERNEL_CAVE, bytes(kernel_code))

        # Set up context
        self._setup_gdt()
        self.teb = thread.Teb & 0xFFFFFFFFFFFFF000
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
        self.info(f"TEB: 0x{self.teb:x}, PEB: 0x{self.peb:x}")
        self.info(f"  ConsoleHandle: 0x{self.console_handle:x}")
        self.info(f"  StandardInput: 0x{self.stdin_handle:x}")
        self.info(f"  StandardOutput: 0x{self.stdout_handle:x}")
        self.info(f"  StandardError: 0x{self.stderr_handle:x}")

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
        except UcError:
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
                except UcError:
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
        syscalls = []
        for export in ntdll.exports:
            if export.name and export.name.startswith("Zw"):
                syscalls.append((export.address, export.name))
            elif export.name == "Wow64Transition":
                patch_addr = self.read_ptr(export.address)
                self.info(f"Patching Wow64Transition: {export.address:x} -> {patch_addr:x}")
                # See: https://opcode0x90.wordpress.com/2007/05/18/kifastsystemcall-hook/
                # mov edx, esp; sysenter; ret
                KiFastSystemCall = b"\x8B\xD4\x0F\x34\xC3"
                self.write(patch_addr, KiFastSystemCall)
            elif export.name == "KiUserExceptionDispatcher":
                self.KiUserExceptionDispatcher = export.address
            elif export.name == "LdrLoadDll":
                self.LdrLoadDll = export.address

        syscalls.sort()
        for index, (rva, name) in enumerate(syscalls):
            cb = syscall_functions.get(name, None)
            argcount = 0
            if cb:
                argspec = inspect.getfullargspec(cb)
                argcount = len(argspec.args) - 1
            self.syscalls.append((name, cb, argcount))

    def push(self, value):
        csp = self.regs.csp - self.ptr_size()
        self.write_ptr(csp, value)
        self.regs.csp = csp

    def read(self, addr, size):
        return self._uc.mem_read(addr, size)

    def write(self, addr, data):
        self._uc.mem_write(addr, data)

    def call(self, addr, args: List[int] = [], regs: dict = {}, count=0):
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
            self.memory.reserve(
                start=self._allocate_base,
                size=self._allocate_size,
                protect=MemoryProtect.PAGE_EXECUTE_READWRITE,
                type=MemoryType.MEM_PRIVATE,
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

    def handle_exception(self):
        assert not self.exception.handling
        self.exception.handling = True

        if self.exception.type == ExceptionType.ContextSwitch:
            self.info(f"switching context, cip: {hex(self.regs.cip)}")
            # Clear the pending exception
            self.last_exception = self.exception
            self.exception = ExceptionInfo()
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
        self.info(f"old csp: {self.regs.csp:x}, new csp: {csp:x}")
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
        if self.exception.type == ExceptionType.Memory:
            record.ExceptionCode = 0xC0000005
            record.ExceptionFlags = 0
            record.ExceptionAddress = self.regs.cip
            record.NumberParameters = 2
            types = {
                UC_MEM_READ_UNMAPPED: EXCEPTION_READ_FAULT,
                UC_MEM_WRITE_UNMAPPED: EXCEPTION_WRITE_FAULT,
                UC_MEM_FETCH_UNMAPPED: EXCEPTION_READ_FAULT,
                UC_MEM_READ_PROT: EXCEPTION_READ_FAULT,
                UC_MEM_WRITE_PROT: EXCEPTION_WRITE_FAULT,
                UC_MEM_FETCH_PROT: EXCEPTION_EXECUTE_FAULT,
            }
            record.ExceptionInformation[0] = types[self.exception.memory_access]
            record.ExceptionInformation[1] = self.exception.memory_address
        elif self.exception.type == ExceptionType.Interrupt and self.exception.interrupt_number == 3:
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
            raise NotImplementedError(f"{self.exception}")  # TODO: implement

        # Clear the pending exception
        self.last_exception = self.exception
        self.exception = ExceptionInfo()

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

    def start(self, begin, end=0xffffffffffffffff, count=0):
        # Clear exceptions before starting
        self.exception = ExceptionInfo()
        emu_begin = begin
        emu_until = end
        emu_count = count
        while True:
            try:
                if self.exception.type != ExceptionType.NoException:
                    if self.exception.final:
                        # Restore the context (unicorn might mess with it before stopping)
                        if self.exception.context is not None:
                            self._uc.context_restore(self.exception.context)
                        try:
                            emu_begin = self.handle_exception()
                        except:
                            traceback.print_exc()
                            self.error(f"exception during exception handling (stack overflow?)")
                            break
                        emu_until = end
                        emu_count = 0
                    else:
                        # If this happens there was an error restarting simulation
                        assert self.exception.step_count == 0

                        # Hook should be installed at this point
                        assert self.exception.code_hook_h is not None

                        # Restore the context (unicorn might mess with it before stopping)
                        assert self.exception.context is not None
                        self._uc.context_restore(self.exception.context)

                        # Restart emulation
                        self.info(f"restarting emulation to handle exception...")
                        emu_begin = self.regs.cip
                        emu_until = 0xffffffffffffffff
                        emu_count = self.exception.tb_icount + 1

                self.info(f"emu_start({emu_begin:x}, {emu_until:x}, {emu_count})")
                self.kill_me = None
                self._uc.emu_start(emu_begin, until=emu_until, count=emu_count)
                self.info(f'emulation finished, cip = {self.regs.cip:x}')
                if self.exit_code is not None:
                    self.info(f"exit code: {self.exit_code:x}")
                break
            except UcError as err:
                if self.kill_me is not None and type(self.kill_me) is not UcError:
                    raise self.kill_me
                if self.exception.type != ExceptionType.NoException:
                    # Handle the exception outside of the except handler
                    continue
                else:
                    self.error(f'error: {err}, cip = {self.regs.cip:x}')
                    traceback.print_exc()
                break

    def stop(self, exit_code=None):
        try:
            self.exit_code = None
            if exit_code is not None:
                self.exit_code = int(exit_code)
        except:
            traceback.print_exc()
            self.error("Invalid type passed to exit_code!")
        self._uc.emu_stop()

    def raise_kill(self, exc=None):
        # HACK: You need to use this to exit from hooks (although it might not always work)
        self.regs.cip = FORCE_KILL_ADDR
        self.kill_me = exc
        if exc is not None:
            raise exc
        else:
            self.kill_me = True
            self._uc.emu_stop()

    def NtCurrentProcess(self):
        return 0xFFFFFFFFFFFFFFFF if self._x64 else 0xFFFFFFFF

    def NtCurrentThread(self):
        return 0xFFFFFFFFFFFFFFFE if self._x64 else 0xFFFFFFFE

    def map_module(self, file_data: bytes, file_path: str = "", requested_base: int = 0, resolve_imports = True):
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
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
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
        argument_ptr = self.allocate(0x1000)
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
        dp.info(f"exception step: {address:x}[{size}]")
        ex = dp.exception
        ex.step_count += 1
        if ex.step_count >= ex.tb_icount:
            raise Exception("Stepped past the basic block without reaching exception")

    except UcError as err:
        dp.error(f"Exception during unicorn hook, please report this as a bug")
        raise err

def _hook_mem(uc: Uc, access, address, size, value, dp: Dumpulator):
    fetch_accesses = [UC_MEM_FETCH, UC_MEM_FETCH_PROT, UC_MEM_FETCH_UNMAPPED]
    if access == UC_MEM_FETCH_UNMAPPED and address >= FORCE_KILL_ADDR - 0x10 and address <= FORCE_KILL_ADDR + 0x10 and dp.kill_me is not None:
        dp.error(f"forced exit memory operation {access} of {address:x}[{size:x}] = {value:X}")
        return False
    if dp.exception.final and access in fetch_accesses:
        dp.info(f"fetch from {hex(address)}[{size}] already reported")
        return False
    # TODO: figure out why when you start executing at 0 this callback is triggered more than once
    try:
        # Extract exception information
        exception = ExceptionInfo()
        exception.type = ExceptionType.Memory
        exception.memory_access = access
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
        final = dp.trace or dp.exception.code_hook_h is not None
        info = "final" if final else "initial"
        if access == UC_MEM_READ_UNMAPPED:
            dp.error(f"{info} unmapped read from {address:x}[{size:x}], cip = {dp.regs.cip:x}, exception: {exception}")
        elif access == UC_MEM_WRITE_UNMAPPED:
            dp.error(f"{info} unmapped write to {address:x}[{size:x}] = {value:x}, cip = {dp.regs.cip:x}")
        elif access == UC_MEM_FETCH_UNMAPPED:
            dp.error(f"{info} unmapped fetch of {address:x}[{size:x}], cip = {dp.regs.rip:x}, cs = {dp.regs.cs:x}")
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
            dp.error(f"{info} unsupported access {names.get(access, str(access))} of {address:x}[{size:x}] = {value:X}, cip = {dp.regs.cip:x}")

        if final:
            # Make sure this is the same exception we expect
            if not dp.trace:
                assert access == dp.exception.memory_access
                assert address == dp.exception.memory_address
                assert size == dp.exception.memory_size
                assert value == dp.exception.memory_value

                # Delete the code hook
                uc.hook_del(int(dp.exception.code_hook_h))
                dp.exception.code_hook_h = None

            # At this point we know for sure the context is correct so we can report the exception
            dp.exception = exception
            dp.exception.final = True

            # Stop emulation (we resume it on KiUserExceptionDispatcher later)
            dp.stop()
            return False

        # There should not be an exception active
        assert dp.exception.type == ExceptionType.NoException

        # Remove the translation block cache for this block
        # Without doing this single stepping the block won't work
        if exception.tb_start != 0:
            uc.ctl_remove_cache(exception.tb_start, exception.tb_start + exception.tb_size)

        # Install the code hook to single step the basic block again.
        # This will prevent translation block caching and give us the correct cip
        exception.code_hook_h = uc.hook_add(UC_HOOK_CODE, _hook_code_exception, user_data=dp)

        # Store the exception info
        dp.exception = exception

        # Stop emulation (we resume execution later)
        dp.stop()
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
        code = dp.read(address, min(size, 15))
        instr = next(dp.cs.disasm(code, address, 1))
    except StopIteration:
        instr = None  # Unsupported instruction
    except UcError:
        instr = None # Likely invalid memory
        code = []
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

    line = f"0x{address:x}{address_name}|"
    if instr is not None:
        line += instr.mnemonic
        if instr.op_str:
            line += " "
            line += instr.op_str
        for reg in _get_regs(instr):
            line += f"|{reg}=0x{dp.regs.__getattr__(reg):x}"
    else:
        line += f"??? (code: {code.hex()}, size: {hex(size)})"
    line += "\n"
    dp.trace.write(line)

def _unicode_string_to_string(dp: Dumpulator, arg: P(UNICODE_STRING)):
    try:
        return arg[0].read_str()
    except UcError:
        pass
    return None

def _object_attributes_to_string(dp: Dumpulator, arg: P(OBJECT_ATTRIBUTES)):
    try:
        return arg[0].ObjectName[0].read_str()
    except UcError:
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
    elif isinstance(arg, PVOID):
        str = hex(arg.ptr)
        tstr = None
        if arg.type is OBJECT_ATTRIBUTES:
            tstr = _object_attributes_to_string(dp, arg)
        elif arg.type is UNICODE_STRING:
            tstr = _unicode_string_to_string(dp, arg)
        if tstr is not None:
            str += f" /* {tstr} */"
        return str
    elif isinstance(arg, int):
        return hex(arg)
    raise NotImplemented()

def _arg_type_string(arg):
    if isinstance(arg, PVOID) and arg.type is not None:
        return arg.type.__name__ + "*"
    return type(arg).__name__

def _hook_interrupt(uc: Uc, number, dp: Dumpulator):
    try:
        # Extract exception information
        exception = ExceptionInfo()
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
        dp.error(f"interrupt {number} ({description}), cip = {dp.regs.cip:x}, cs = {dp.regs.cs:x}")

        # There should not be an exception active
        assert dp.exception.type == ExceptionType.NoException

        # At this point we know for sure the context is correct so we can report the exception
        dp.exception = exception
        dp.exception.final = True
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
    index = dp.regs.cax & 0xffff
    if index < len(dp.syscalls):
        name, syscall_impl, argcount = dp.syscalls[index]
        if syscall_impl:
            argspec = inspect.getfullargspec(syscall_impl)
            args = []

            def syscall_arg(index):
                if index == 0 and dp.ptr_size() == 8:
                    return dp.regs.r10
                return dp.args[index]

            dp.info(f"syscall: {name}(")
            for i in range(0, argcount):
                argname = argspec.args[1 + i]
                argtype = argspec.annotations[argname]
                argvalue = syscall_arg(i)
                if issubclass(argtype, PVOID):
                    argvalue = argtype(argvalue, dp)
                elif issubclass(argtype, Enum):
                    try:
                        argvalue = argtype(dp.args[i] & 0xFFFFFFFF)
                    except KeyError as x:
                        raise Exception(f"Unknown enum value {dp.args[i]} for {type(argtype)}")
                else:
                    argvalue = argtype(argvalue)
                args.append(argvalue)

                comma = ","
                if i + 1 == argcount:
                    comma = ""

                dp.info(f"    {_arg_type_string(argvalue)} {argname} = {_arg_to_string(dp, argvalue)}{comma}")
            dp.info(")")
            try:
                status = syscall_impl(dp, *args)
                if isinstance(status, ExceptionInfo):
                    print("context switch, stopping emulation")
                    dp.exception = status
                    dp.raise_kill(UcError(UC_ERR_EXCEPTION))
                else:
                    dp.info(f"status = {status:x}")
                    dp.regs.cax = status
                    if dp._x64:
                        dp.regs.rcx = dp.regs.cip + 2
                        dp.regs.r11 = dp.regs.eflags
            except UcError as err:
                raise err
            except Exception as exc:
                traceback.print_exc()
                dp.error(f"Exception thrown during syscall implementation, stopping emulation!")
                dp.raise_kill(exc)
        else:
            dp.error(f"syscall index: {index:x} -> {name} not implemented!")
            dp.raise_kill(NotImplementedError())
    else:
        dp.error(f"syscall index {index:x} out of range")
        dp.raise_kill(IndexError())

def _emulate_unsupported_instruction(dp: Dumpulator, instr: CsInsn):
    if instr.id == X86_INS_RDRAND:
        op: X86Op = instr.operands[0]
        regname = instr.reg_name(op.reg)
        if dp._x64 and op.size * 8 == 32:
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
    # HACK: unicorn cannot gracefully exit in all contexts
    if dp.kill_me:
        dp.error(f"terminating emulation...")
        return False
    dp.error(f"invalid instruction at {address:x}")
    try:
        code = dp.read(address, 15)
        instr = next(dp.cs.disasm(code, address, 1))
        if _emulate_unsupported_instruction(dp, instr):
            # Resume execution with a context switch
            assert dp.exception.type == ExceptionType.NoException
            exception = ExceptionInfo()
            exception.type = ExceptionType.ContextSwitch
            exception.final = True
            dp.exception = exception
            return False  # NOTE: returning True would stop emulation
    except StopIteration:
        pass  # Unsupported instruction
    except UcError:
        pass  # Invalid memory access (NOTE: this should not be possible actually)
    raise NotImplementedError("TODO: throw invalid instruction exception")
    return False
