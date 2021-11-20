from enum import Enum

from minidump.minidumpfile import *
from unicorn import *
from unicorn.x86_const import *
from pefile import *
import inspect
from .native import *

syscall_functions = {}


F_GRANULARITY = 0x8
F_PROT_32 = 0x4
F_LONG = 0x2
F_AVAILABLE = 0x1

A_PRESENT = 0x80

A_PRIV_3 = 0x60
A_PRIV_2 = 0x40
A_PRIV_1 = 0x20
A_PRIV_0 = 0x0

A_CODE = 0x10
A_DATA = 0x10
A_TSS = 0x0
A_GATE = 0x0

A_DATA_WRITABLE = 0x2
A_CODE_READABLE = 0x2

A_DIR_CON_BIT = 0x4

S_GDT = 0x0
S_LDT = 0x4
S_PRIV_3 = 0x3
S_PRIV_2 = 0x2
S_PRIV_1 = 0x1
S_PRIV_0 = 0x0

GDT_ADDR = 0x3000
GDT_LIMIT = 0x1000
GDT_ENTRY_SIZE = 0x8

CAVE_ADDR = 0x5000
CAVE_SIZE = 0x1000

def create_selector(idx, flags):
    to_ret = flags
    to_ret |= idx << 3
    return to_ret


# https://wiki.osdev.org/GDT#Segment_Descriptor
def create_gdt_entry(base, limit, access, flags):
    to_ret = limit & 0xffff
    to_ret |= (base & 0xffffff) << 16
    to_ret |= (access & 0xff) << 40
    to_ret |= ((limit >> 16) & 0xf) << 48
    to_ret |= (flags & 0xff) << 52
    to_ret |= ((base >> 24) & 0xff) << 56
    return struct.pack('<Q', to_ret)


def map_unicorn_perms(protect: AllocationProtect):
    mapping = {
        AllocationProtect.PAGE_EXECUTE: UC_PROT_EXEC | UC_PROT_READ,
        AllocationProtect.PAGE_EXECUTE_READ: UC_PROT_EXEC | UC_PROT_READ,
        AllocationProtect.PAGE_EXECUTE_READWRITE: UC_PROT_ALL,
        AllocationProtect.PAGE_EXECUTE_WRITECOPY: UC_PROT_ALL,
        AllocationProtect.PAGE_NOACCESS: UC_PROT_NONE,
        AllocationProtect.PAGE_READONLY: UC_PROT_READ,
        AllocationProtect.PAGE_READWRITE: UC_PROT_READ | UC_PROT_WRITE,
        AllocationProtect.PAGE_WRITECOPY: UC_PROT_READ | UC_PROT_WRITE,
    }
    return mapping.get(protect, UC_PROT_NONE)


class Registers:
    def __init__(self, uc: Uc):
        self._uc = uc

    @property
    def rsp(self):
        return self._uc.reg_read(UC_X86_REG_RSP)

    @property
    def rip(self):
        return self._uc.reg_read(UC_X86_REG_RIP)

    @property
    def rax(self):
        return self._uc.reg_read(UC_X86_REG_RAX)

    @property
    def r8(self):
        return self._uc.reg_read(UC_X86_REG_R8)


class Arguments:
    def __init__(self, uc: Uc):
        self._uc = uc

    def __getitem__(self, index):
        if index == 0:
            return self._uc.reg_read(UC_X86_REG_RCX)
        elif index == 1:
            return self._uc.reg_read(UC_X86_REG_RDX)
        elif index == 2:
            return self._uc.reg_read(UC_X86_REG_R8)
        elif index == 3:
            return self._uc.reg_read(UC_X86_REG_R9)
        elif index < 20:
            rsp = self._uc.reg_read(UC_X86_REG_RSP)
            arg_addr = rsp + (index + 1) * 8
            data = self._uc.mem_read(arg_addr, 8)
            return struct.unpack("<Q", data)[0]
        else:
            raise Exception("not implemented!")

    def __setitem__(self, index, value):
        if index == 0:
            self._uc.reg_write(UC_X86_REG_RCX, value)
        elif index == 1:
            self._uc.reg_write(UC_X86_REG_RDX, value)
        elif index == 2:
            self._uc.reg_write(UC_X86_REG_R8, value)
        elif index == 3:
            self._uc.reg_write(UC_X86_REG_R9, value)
        raise NotImplemented()


class Dumpulator:
    def __init__(self, minidump_file, trace=False):
        self._minidump = MinidumpFile.parse(minidump_file)
        self._memory = self._minidump.get_reader().get_buffered_reader()
        self._uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.regs = Registers(self._uc)
        self.args = Arguments(self._uc)
        self._allocate_base = None
        self._allocate_size = 0x10000
        self._allocate_ptr = None
        self._setup_emulator(trace)
        self.exit_code = None
        self.syscalls = []
        self._setup_syscalls()
        os.environ["PYTHONUNBUFFERED"] = "1"

    def _unbuffered_output(self):
        class Unbuffered(object):
            def __init__(self, stream):
                self.stream = stream

            def write(self, data):
                self.stream.write(data)
                self.stream.flush()

            def writelines(self, datas):
                self.stream.writelines(datas)
                self.stream.flush()

            def __getattr__(self, attr):
                return getattr(self.stream, attr)

        import sys
        sys.stdout = Unbuffered(sys.stdout)
        sys.stderr = Unbuffered(sys.stderr)

    def _setup_emulator(self, trace):
        # set up hooks
        self._uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_READ_PROT | UC_HOOK_MEM_WRITE_PROT | UC_HOOK_MEM_FETCH_PROT, _hook_mem, user_data=self)
        #self._uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, _hook_mem, user_data=self)
        if trace:
            self._uc.hook_add(UC_HOOK_CODE, _hook_code, user_data=self)
        #self._uc.hook_add(UC_HOOK_MEM_READ_INVALID, self._hook_mem, user_data=None)
        #self._uc.hook_add(UC_HOOK_MEM_WRITE_INVALID, self._hook_mem, user_data=None)
        self._uc.hook_add(UC_HOOK_INSN, _hook_syscall, user_data=self, arg1=UC_X86_INS_SYSCALL)
        self._uc.hook_add(UC_HOOK_INTR, _hook_interrupt, user_data=self)

        # map in page for memory allocations
        #self._uc.mem_map(self._allocate_base, self._allocate_size)

        # map in codecave
        self._uc.mem_map(CAVE_ADDR, CAVE_SIZE)
        self._uc.mem_write(CAVE_ADDR, b"\xCC" * CAVE_SIZE)

        info: MinidumpMemoryInfo
        for info in self._minidump.memory_info.infos:
            if info.State == MemoryState.MEM_COMMIT:
                print(f"mapped base: 0x{info.BaseAddress:x}, size: 0x{info.RegionSize:x}, protect: {info.Protect}")
                self._uc.mem_map(info.BaseAddress, info.RegionSize, map_unicorn_perms(info.Protect))
            elif info.State == MemoryState.MEM_FREE and info.BaseAddress > 0x10000 and info.RegionSize >= self._allocate_size:
                self._allocate_base = info.BaseAddress

        seg: MinidumpMemorySegment
        for seg in self._minidump.memory_segments_64.memory_segments:
            print(f"initialize base: 0x{seg.start_virtual_address:x}, size: 0x{seg.size:x}")
            self._memory.move(seg.start_virtual_address)
            assert self._memory.current_position == seg.start_virtual_address
            data = self._memory.read(seg.size)
            self._uc.mem_write(seg.start_virtual_address, data)

        thread: MINIDUMP_THREAD
        thread = self._minidump.threads.threads[0]
        context: CONTEXT = thread.ContextObject
        self._uc.reg_write(UC_X86_REG_MXCSR, context.MxCsr)
        #self._uc.reg_write(UC_X86_REG_CS, context.SegCs)
        #self._uc.reg_write(UC_X86_REG_DS, context.SegDs)
        #self._uc.reg_write(UC_X86_REG_ES, context.SegEs)
        #self.uc.reg_write(UC_X86_REG_FS, context.SegFs)
        #self.uc.reg_write(UC_X86_REG_GS, context.SegGs)
        #self._uc.reg_write(UC_X86_REG_SS, context.SegSs)
        self._uc.reg_write(UC_X86_REG_EFLAGS, context.EFlags)
        self._uc.reg_write(UC_X86_REG_DR0, context.Dr0)
        self._uc.reg_write(UC_X86_REG_DR1, context.Dr1)
        self._uc.reg_write(UC_X86_REG_DR2, context.Dr2)
        self._uc.reg_write(UC_X86_REG_DR3, context.Dr3)
        self._uc.reg_write(UC_X86_REG_DR6, context.Dr6)
        self._uc.reg_write(UC_X86_REG_DR7, context.Dr7)
        self._uc.reg_write(UC_X86_REG_RAX, context.Rax)
        self._uc.reg_write(UC_X86_REG_RCX, context.Rcx)
        self._uc.reg_write(UC_X86_REG_RDX, context.Rdx)
        self._uc.reg_write(UC_X86_REG_RBX, context.Rbx)
        self._uc.reg_write(UC_X86_REG_RSP, context.Rsp)
        self._uc.reg_write(UC_X86_REG_RBP, context.Rbp)
        self._uc.reg_write(UC_X86_REG_RSI, context.Rsi)
        self._uc.reg_write(UC_X86_REG_RDI, context.Rdi)
        self._uc.reg_write(UC_X86_REG_R8, context.R8)
        self._uc.reg_write(UC_X86_REG_R9, context.R9)
        self._uc.reg_write(UC_X86_REG_R10, context.R10)
        self._uc.reg_write(UC_X86_REG_R11, context.R11)
        self._uc.reg_write(UC_X86_REG_R12, context.R12)
        self._uc.reg_write(UC_X86_REG_R13, context.R13)
        self._uc.reg_write(UC_X86_REG_R14, context.R14)
        self._uc.reg_write(UC_X86_REG_R15, context.R15)
        self._uc.reg_write(UC_X86_REG_RIP, context.Rip)

        # Source: https://github.com/unicorn-engine/unicorn/blob/f1f59bac5542776fe85fb225a88d5cc623f89b87/tests/regress/x86_gdt.py
        # set up GDT (TEB)
        if False:
            self._uc.mem_map(GDT_ADDR, GDT_LIMIT)
            gdt_entry = create_gdt_entry(0xEDB7F92000, 0x1000, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3,
                                         F_PROT_32)
            self._uc.mem_write(GDT_ADDR + 8, gdt_entry)
            self._uc.reg_write(UC_X86_REG_GDTR, (0, GDT_ADDR, GDT_LIMIT, 0x0))
            selector = create_selector(1, S_GDT | S_PRIV_3)
            print(f"FS = {selector:0x}")
            self._uc.reg_write(UC_X86_REG_FS, selector)
            self._uc.reg_write(UC_X86_REG_FS_BASE, thread.Teb)
        else:
            # self._uc.mem_map(GDT_ADDR, GDT_LIMIT)
            # gdt_entry = create_gdt_entry(0, 0, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3, F_PROT_32 | F_LONG)
            # win_gs = 0x2b
            # gdt_index = (win_gs & ~7) >> 3
            # self._uc.mem_write(GDT_ADDR + gdt_index * 8, gdt_entry)
            # self._uc.reg_write(UC_X86_REG_GDTR, (0, GDT_ADDR, GDT_LIMIT, 0x0))
            # selector = create_selector(gdt_index, S_GDT | S_PRIV_3)
            # print(f"GS = {selector:0x}")
            # self._uc.reg_write(UC_X86_REG_GS, selector)
            self._uc.reg_write(UC_X86_REG_GS_BASE, thread.Teb)
            pass

    def _find_module(self, name) -> MinidumpModule:
        module: MinidumpModule
        for module in self._minidump.modules.modules:
            filename = module.name.split('\\')[-1].lower()
            if filename == name.lower():
                return module
        raise Exception(f"Module '{name}' not found")

    def _setup_syscalls(self):
        # Load the ntdll module from memory
        ntdll = self._find_module("ntdll.dll")
        ntdll_data = self.read(ntdll.baseaddress, ntdll.size)
        pe = PE(data=ntdll_data, fast_load=True)
        # Hack to adjust pefile to accept in-memory modules
        for section in pe.sections:
            # Potentially interesting members: Misc_PhysicalAddress, Misc_VirtualSize, SizeOfRawData
            section.PointerToRawData = section.VirtualAddress
            section.PointerToRawData_adj = section.VirtualAddress
        # Parser exports and find the syscall indices
        pe.parse_data_directories(directories=[DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        syscalls = []
        for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if export.name and export.name.startswith(b"Zw"):
                syscalls.append((export.address, export.name.decode("utf-8")))
        syscalls.sort()
        for index, (rva, name) in enumerate(syscalls):
            cb = syscall_functions.get(name, None)
            argcount = 0
            if cb:
                argspec = inspect.getfullargspec(cb)
                argcount = len(argspec.args) - 1
            self.syscalls.append((name, cb, argcount))

    def push(self, value):
        rsp = self._uc.reg_read(UC_X86_REG_RSP) - 8
        self._uc.mem_write(rsp, struct.pack('<Q', value))
        self._uc.reg_write(UC_X86_REG_RSP, rsp)

    def read(self, addr, size):
        return self._uc.mem_read(addr, size)

    def read_ptr(self, addr):
        return struct.unpack("<Q", self.read(addr, 8))[0]

    def read_ulong(self, addr):
        return struct.unpack("<I", self.read(addr, 4))[0]

    def read_long(self, addr):
        return struct.unpack("<i", self.read(addr, 4))[0]

    def write(self, addr, data):
        return self._uc.mem_write(addr, data)

    def write_ulong(self, addr, value):
        return self._uc.mem_write(addr, struct.pack("<I", value))

    def write_long(self, addr, value):
        return self._uc.mem_write(addr, struct.pack("<i", value))

    def write_ptr(self, addr, value):
        return self._uc.mem_write(addr, struct.pack("<Q", value))

    def call(self, addr, args):
        # push return address
        self.push(CAVE_ADDR)
        # set up arguments
        i = 0
        while i < len(args):
            self._set_arg(i, args[i])
            i += 1
        self.start(addr, end=CAVE_SIZE)
        return self._uc.reg_read(UC_X86_REG_RAX)

    def read_str(self, addr, encoding="utf-8"):
        data = self.read(addr, 512)
        nullidx = data.find(b'\0')
        if nullidx != -1:
            data = data[:nullidx]
        return data.decode(encoding)

    def allocate(self, size):
        if not self._allocate_ptr:
            self._uc.mem_map(self._allocate_base, self._allocate_size)
            self._allocate_ptr = self._allocate_base

        ptr = self._allocate_ptr + size
        if ptr > self._allocate_base + self._allocate_size:
            raise Exception("not enough room to allocate!")
        self._allocate_ptr = ptr
        return ptr

    def _set_arg(self, index, value):
        if index == 0:
            self._uc.reg_write(UC_X86_REG_RCX, value)
        elif index == 1:
            self._uc.reg_write(UC_X86_REG_RDX, value)
        elif index == 2:
            self._uc.reg_write(UC_X86_REG_R8, value)
        elif index == 3:
            self._uc.reg_write(UC_X86_REG_R9, value)
        else:
            raise Exception(f'argument index {index} not supported!')
        pass

    def start(self, begin, end=0xffffffffffffffff, count=0):
        try:
            self._uc.emu_start(begin, until=end, count=count)
            print(f'emulation finished, rip = 0x{self._uc.reg_read(UC_X86_REG_RIP):x}')
            if self.exit_code is not None:
                print(f"exit code: {self.exit_code}")
        except UcError as err:
            print(f'error: {err}, rip = 0x{self._uc.reg_read(UC_X86_REG_RIP):x}')

    def stop(self, exit_code=None):
        self.exit_code = int(exit_code)
        self._uc.emu_stop()


def _hook_mem(uc: Uc, access, address, size, value, dp: Dumpulator):
    if access == UC_MEM_READ_UNMAPPED:
        print(f"unmapped read from {address:0x}[{size:0x}], rip = {uc.reg_read(UC_X86_REG_RIP):0x}")
    elif access == UC_MEM_WRITE_UNMAPPED:
        print(f"unmapped write to {address:0x}[{size:0x}] = {value:0x}, rip = {uc.reg_read(UC_X86_REG_RIP):0x}, rax: {dp.regs.rax:0x}")
        data = dp.read(dp.regs.rsp, 8)
        instr = dp.read(dp.regs.rip, 16)
        print(f"instr: {instr.hex()}")
        [ret] = struct.unpack('<Q', data)
        print(f"r8: {dp.regs.r8:0x}")

    elif access == UC_MEM_FETCH_UNMAPPED:
        print(f"unmapped fetch of {address:0x}[{size:0x}] = {value:0x}, rip = {uc.reg_read(UC_X86_REG_RIP):0x}")
    return False


def _hook_code(uc: Uc, address, size, dp: Dumpulator):
    print(f"instruction: {address:0x} {dp.read(address, size).hex()}")
    return True


def _arg_to_string(arg):
    if isinstance(arg, Enum):
        return arg.name
    elif isinstance(arg, int):
        return hex(arg)
    elif isinstance(arg, PVOID):
        return hex(arg.ptr)
    raise NotImplemented()


def _arg_type_string(arg):
    if isinstance(arg, PVOID) and arg.type is not None:
        return arg.type.__name__ + "*"
    return type(arg).__name__


def _hook_interrupt(uc: Uc, number, dp: Dumpulator):
    print(f"interrupt {number}, rip = {dp.regs.rip:0x}")
    uc.emu_stop()


def _hook_syscall(uc: Uc, dp: Dumpulator):
    index = dp.regs.rax
    if index < len(dp.syscalls):
        name, cb, argcount = dp.syscalls[index]
        if cb:
            argspec = inspect.getfullargspec(cb)
            args = []

            print(f"syscall: {name}(")
            for i in range(0, argcount):
                argname = argspec.args[1 + i]
                argtype = argspec.annotations[argname]
                if issubclass(argtype, PVOID):
                    argvalue = argtype(dp.args[i], dp.read)
                else:
                    argvalue = argtype(dp.args[i])
                args.append(argvalue)

                comma = ","
                if i + 1 == argcount:
                    comma = ""

                print(f"    {_arg_type_string(argvalue)} {argname} = {_arg_to_string(argvalue)}{comma}")
            print(")")
            status = cb(dp, *args)
            print(f"status = {status:x}")
            uc.reg_write(UC_X86_REG_RAX, status)
        else:
            print(f"syscall index: {index:0x} -> {name} not implemented!")
            uc.emu_stop()
    else:
        print(f"syscall index {index:0x} out of range")
        uc.emu_stop()
