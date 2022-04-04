import traceback
from enum import Enum
from typing import List, Union

from minidump.minidumpfile import *
from unicorn import *
from unicorn.x86_const import *
from pefile import *
import inspect
from .native import *
from capstone import *
from collections import OrderedDict

syscall_functions = {}


CAVE_ADDR = 0x5000
CAVE_SIZE = 0x1000
# GDT Constants needed to set our emulator into protected mode
# Access bits
class GDT_ACCESS_BITS:
    ProtMode32 = 0x4
    PresentBit = 0x80
    Ring3 = 0x60
    Ring0 = 0
    DataWritable = 0x2
    CodeReadable = 0x2
    DirectionConformingBit = 0x4
    Code = 0x18
    Data = 0x10

class GDT_FLAGS:
    Ring3 = 0x3
    Ring0 = 0


def map_unicorn_perms(protect: AllocationProtect):
    if isinstance(protect, int):
        protect = AllocationProtect(protect)
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
    def __init__(self, uc: Uc, x64):
        self._uc = uc
        self._x64 = x64
        self._regmap = {
            "ah": UC_X86_REG_AH,
            "al": UC_X86_REG_AL,
            "ax": UC_X86_REG_AX,
            "bh": UC_X86_REG_BH,
            "bl": UC_X86_REG_BL,
            "bp": UC_X86_REG_BP,
            "bpl": UC_X86_REG_BPL,
            "bx": UC_X86_REG_BX,
            "ch": UC_X86_REG_CH,
            "cl": UC_X86_REG_CL,
            "cs": UC_X86_REG_CS,
            "cx": UC_X86_REG_CX,
            "dh": UC_X86_REG_DH,
            "di": UC_X86_REG_DI,
            "dil": UC_X86_REG_DIL,
            "dl": UC_X86_REG_DL,
            "ds": UC_X86_REG_DS,
            "dx": UC_X86_REG_DX,
            "eax": UC_X86_REG_EAX,
            "ebp": UC_X86_REG_EBP,
            "ebx": UC_X86_REG_EBX,
            "ecx": UC_X86_REG_ECX,
            "edi": UC_X86_REG_EDI,
            "edx": UC_X86_REG_EDX,
            "eflags": UC_X86_REG_EFLAGS,
            "eip": UC_X86_REG_EIP,
            "es": UC_X86_REG_ES,
            "esi": UC_X86_REG_ESI,
            "esp": UC_X86_REG_ESP,
            "fpsw": UC_X86_REG_FPSW,
            "fs": UC_X86_REG_FS,
            "gs": UC_X86_REG_GS,
            "ip": UC_X86_REG_IP,
            "rax": UC_X86_REG_RAX,
            "rbp": UC_X86_REG_RBP,
            "rbx": UC_X86_REG_RBX,
            "rcx": UC_X86_REG_RCX,
            "rdi": UC_X86_REG_RDI,
            "rdx": UC_X86_REG_RDX,
            "rip": UC_X86_REG_RIP,
            "rsi": UC_X86_REG_RSI,
            "rsp": UC_X86_REG_RSP,
            "si": UC_X86_REG_SI,
            "sil": UC_X86_REG_SIL,
            "sp": UC_X86_REG_SP,
            "spl": UC_X86_REG_SPL,
            "ss": UC_X86_REG_SS,
            "cr0": UC_X86_REG_CR0,
            "cr1": UC_X86_REG_CR1,
            "cr2": UC_X86_REG_CR2,
            "cr3": UC_X86_REG_CR3,
            "cr4": UC_X86_REG_CR4,
            "cr8": UC_X86_REG_CR8,
            "dr0": UC_X86_REG_DR0,
            "dr1": UC_X86_REG_DR1,
            "dr2": UC_X86_REG_DR2,
            "dr3": UC_X86_REG_DR3,
            "dr4": UC_X86_REG_DR4,
            "dr5": UC_X86_REG_DR5,
            "dr6": UC_X86_REG_DR6,
            "dr7": UC_X86_REG_DR7,
            "fp0": UC_X86_REG_FP0,
            "fp1": UC_X86_REG_FP1,
            "fp2": UC_X86_REG_FP2,
            "fp3": UC_X86_REG_FP3,
            "fp4": UC_X86_REG_FP4,
            "fp5": UC_X86_REG_FP5,
            "fp6": UC_X86_REG_FP6,
            "fp7": UC_X86_REG_FP7,
            "k0": UC_X86_REG_K0,
            "k1": UC_X86_REG_K1,
            "k2": UC_X86_REG_K2,
            "k3": UC_X86_REG_K3,
            "k4": UC_X86_REG_K4,
            "k5": UC_X86_REG_K5,
            "k6": UC_X86_REG_K6,
            "k7": UC_X86_REG_K7,
            "mm0": UC_X86_REG_MM0,
            "mm1": UC_X86_REG_MM1,
            "mm2": UC_X86_REG_MM2,
            "mm3": UC_X86_REG_MM3,
            "mm4": UC_X86_REG_MM4,
            "mm5": UC_X86_REG_MM5,
            "mm6": UC_X86_REG_MM6,
            "mm7": UC_X86_REG_MM7,
            "r8": UC_X86_REG_R8,
            "r9": UC_X86_REG_R9,
            "r10": UC_X86_REG_R10,
            "r11": UC_X86_REG_R11,
            "r12": UC_X86_REG_R12,
            "r13": UC_X86_REG_R13,
            "r14": UC_X86_REG_R14,
            "r15": UC_X86_REG_R15,
            "st0": UC_X86_REG_ST0,
            "st1": UC_X86_REG_ST1,
            "st2": UC_X86_REG_ST2,
            "st3": UC_X86_REG_ST3,
            "st4": UC_X86_REG_ST4,
            "st5": UC_X86_REG_ST5,
            "st6": UC_X86_REG_ST6,
            "st7": UC_X86_REG_ST7,
            "xmm0": UC_X86_REG_XMM0,
            "xmm1": UC_X86_REG_XMM1,
            "xmm2": UC_X86_REG_XMM2,
            "xmm3": UC_X86_REG_XMM3,
            "xmm4": UC_X86_REG_XMM4,
            "xmm5": UC_X86_REG_XMM5,
            "xmm6": UC_X86_REG_XMM6,
            "xmm7": UC_X86_REG_XMM7,
            "xmm8": UC_X86_REG_XMM8,
            "xmm9": UC_X86_REG_XMM9,
            "xmm10": UC_X86_REG_XMM10,
            "xmm11": UC_X86_REG_XMM11,
            "xmm12": UC_X86_REG_XMM12,
            "xmm13": UC_X86_REG_XMM13,
            "xmm14": UC_X86_REG_XMM14,
            "xmm15": UC_X86_REG_XMM15,
            "xmm16": UC_X86_REG_XMM16,
            "xmm17": UC_X86_REG_XMM17,
            "xmm18": UC_X86_REG_XMM18,
            "xmm19": UC_X86_REG_XMM19,
            "xmm20": UC_X86_REG_XMM20,
            "xmm21": UC_X86_REG_XMM21,
            "xmm22": UC_X86_REG_XMM22,
            "xmm23": UC_X86_REG_XMM23,
            "xmm24": UC_X86_REG_XMM24,
            "xmm25": UC_X86_REG_XMM25,
            "xmm26": UC_X86_REG_XMM26,
            "xmm27": UC_X86_REG_XMM27,
            "xmm28": UC_X86_REG_XMM28,
            "xmm29": UC_X86_REG_XMM29,
            "xmm30": UC_X86_REG_XMM30,
            "xmm31": UC_X86_REG_XMM31,
            "ymm0": UC_X86_REG_YMM0,
            "ymm1": UC_X86_REG_YMM1,
            "ymm2": UC_X86_REG_YMM2,
            "ymm3": UC_X86_REG_YMM3,
            "ymm4": UC_X86_REG_YMM4,
            "ymm5": UC_X86_REG_YMM5,
            "ymm6": UC_X86_REG_YMM6,
            "ymm7": UC_X86_REG_YMM7,
            "ymm8": UC_X86_REG_YMM8,
            "ymm9": UC_X86_REG_YMM9,
            "ymm10": UC_X86_REG_YMM10,
            "ymm11": UC_X86_REG_YMM11,
            "ymm12": UC_X86_REG_YMM12,
            "ymm13": UC_X86_REG_YMM13,
            "ymm14": UC_X86_REG_YMM14,
            "ymm15": UC_X86_REG_YMM15,
            "ymm16": UC_X86_REG_YMM16,
            "ymm17": UC_X86_REG_YMM17,
            "ymm18": UC_X86_REG_YMM18,
            "ymm19": UC_X86_REG_YMM19,
            "ymm20": UC_X86_REG_YMM20,
            "ymm21": UC_X86_REG_YMM21,
            "ymm22": UC_X86_REG_YMM22,
            "ymm23": UC_X86_REG_YMM23,
            "ymm24": UC_X86_REG_YMM24,
            "ymm25": UC_X86_REG_YMM25,
            "ymm26": UC_X86_REG_YMM26,
            "ymm27": UC_X86_REG_YMM27,
            "ymm28": UC_X86_REG_YMM28,
            "ymm29": UC_X86_REG_YMM29,
            "ymm30": UC_X86_REG_YMM30,
            "ymm31": UC_X86_REG_YMM31,
            "zmm0": UC_X86_REG_ZMM0,
            "zmm1": UC_X86_REG_ZMM1,
            "zmm2": UC_X86_REG_ZMM2,
            "zmm3": UC_X86_REG_ZMM3,
            "zmm4": UC_X86_REG_ZMM4,
            "zmm5": UC_X86_REG_ZMM5,
            "zmm6": UC_X86_REG_ZMM6,
            "zmm7": UC_X86_REG_ZMM7,
            "zmm8": UC_X86_REG_ZMM8,
            "zmm9": UC_X86_REG_ZMM9,
            "zmm10": UC_X86_REG_ZMM10,
            "zmm11": UC_X86_REG_ZMM11,
            "zmm12": UC_X86_REG_ZMM12,
            "zmm13": UC_X86_REG_ZMM13,
            "zmm14": UC_X86_REG_ZMM14,
            "zmm15": UC_X86_REG_ZMM15,
            "zmm16": UC_X86_REG_ZMM16,
            "zmm17": UC_X86_REG_ZMM17,
            "zmm18": UC_X86_REG_ZMM18,
            "zmm19": UC_X86_REG_ZMM19,
            "zmm20": UC_X86_REG_ZMM20,
            "zmm21": UC_X86_REG_ZMM21,
            "zmm22": UC_X86_REG_ZMM22,
            "zmm23": UC_X86_REG_ZMM23,
            "zmm24": UC_X86_REG_ZMM24,
            "zmm25": UC_X86_REG_ZMM25,
            "zmm26": UC_X86_REG_ZMM26,
            "zmm27": UC_X86_REG_ZMM27,
            "zmm28": UC_X86_REG_ZMM28,
            "zmm29": UC_X86_REG_ZMM29,
            "zmm30": UC_X86_REG_ZMM30,
            "zmm31": UC_X86_REG_ZMM31,
            "r8b": UC_X86_REG_R8B,
            "r9b": UC_X86_REG_R9B,
            "r10b": UC_X86_REG_R10B,
            "r11b": UC_X86_REG_R11B,
            "r12b": UC_X86_REG_R12B,
            "r13b": UC_X86_REG_R13B,
            "r14b": UC_X86_REG_R14B,
            "r15b": UC_X86_REG_R15B,
            "r8d": UC_X86_REG_R8D,
            "r9d": UC_X86_REG_R9D,
            "r10d": UC_X86_REG_R10D,
            "r11d": UC_X86_REG_R11D,
            "r12d": UC_X86_REG_R12D,
            "r13d": UC_X86_REG_R13D,
            "r14d": UC_X86_REG_R14D,
            "r15d": UC_X86_REG_R15D,
            "r8w": UC_X86_REG_R8W,
            "r9w": UC_X86_REG_R9W,
            "r10w": UC_X86_REG_R10W,
            "r11w": UC_X86_REG_R11W,
            "r12w": UC_X86_REG_R12W,
            "r13w": UC_X86_REG_R13W,
            "r14w": UC_X86_REG_R14W,
            "r15w": UC_X86_REG_R15W,
            "idtr": UC_X86_REG_IDTR,
            "gdtr": UC_X86_REG_GDTR,
            "ldtr": UC_X86_REG_LDTR,
            "tr": UC_X86_REG_TR,
            "fpcw": UC_X86_REG_FPCW,
            "fptag": UC_X86_REG_FPTAG,
            "msr": UC_X86_REG_MSR,
            "mxcsr": UC_X86_REG_MXCSR,
            "fs_base": UC_X86_REG_FS_BASE,
            "gs_base": UC_X86_REG_GS_BASE,
        }
        if unicorn.__version__[0] < '2':
            self._regmap.update({
                "riz": UC_X86_REG_RIZ,
                "cr5": UC_X86_REG_CR5,
                "cr6": UC_X86_REG_CR6,
                "cr7": UC_X86_REG_CR7,
                "cr9": UC_X86_REG_CR9,
                "cr10": UC_X86_REG_CR10,
                "cr11": UC_X86_REG_CR11,
                "cr12": UC_X86_REG_CR12,
                "cr13": UC_X86_REG_CR13,
                "cr14": UC_X86_REG_CR14,
                "cr15": UC_X86_REG_CR15,
                "dr8": UC_X86_REG_DR8,
                "dr9": UC_X86_REG_DR9,
                "dr10": UC_X86_REG_DR10,
                "dr11": UC_X86_REG_DR11,
                "dr12": UC_X86_REG_DR12,
                "dr13": UC_X86_REG_DR13,
                "dr14": UC_X86_REG_DR14,
                "dr15": UC_X86_REG_DR15,
                "rflags": UC_X86_REG_EFLAGS,
            })
        else:
            self._regmap.update({
                "flags": UC_X86_REG_FLAGS,
                "rflags": UC_X86_REG_RFLAGS
            })
        if self._x64:
            self._regmap.update({
                "cax": UC_X86_REG_RAX,
                "cbx": UC_X86_REG_RBX,
                "ccx": UC_X86_REG_RCX,
                "cdx": UC_X86_REG_RDX,
                "cbp": UC_X86_REG_RBP,
                "csp": UC_X86_REG_RSP,
                "csi": UC_X86_REG_RSI,
                "cdi": UC_X86_REG_RDI,
                "cip": UC_X86_REG_RIP,
            })
        else:
            self._regmap.update({
                "cax": UC_X86_REG_EAX,
                "cbx": UC_X86_REG_EBX,
                "ccx": UC_X86_REG_ECX,
                "cdx": UC_X86_REG_EDX,
                "cbp": UC_X86_REG_EBP,
                "csp": UC_X86_REG_ESP,
                "csi": UC_X86_REG_ESI,
                "cdi": UC_X86_REG_EDI,
                "cip": UC_X86_REG_EIP,
            })

    def __getattr__(self, name: str):
        return self._uc.reg_read(self._regmap[name])

    def __setattr__(self, name: str, value):
        if name.startswith("_"):
            object.__setattr__(self, name, value)
        else:
            self._uc.reg_write(self._regmap[name], value)

    # value = dp.regs[myname]
    def __getitem__(self, name: str):
        return self.__getattr__(name)

    # dp.regs[myname] = value
    def __setitem__(self, name: str, value):
        return self.__setattr__(name, value)


class Arguments:
    def __init__(self, uc: Uc, regs: Registers, x64):
        self._uc = uc
        self._regs = regs
        self._x64 = x64

    def __getitem__(self, index):
        regs = self._regs

        if not self._x64:
            arg_addr = regs.esp + (index + 2) * 4
            data = self._uc.mem_read(arg_addr, 4)
            return struct.unpack("<I", data)[0]

        if index == 0:
            return regs.rcx
        elif index == 1:
            return regs.rdx
        elif index == 2:
            return regs.r8
        elif index == 3:
            return regs.r9
        elif index < 20:
            arg_addr = regs.rsp + (index + 1) * 8
            data = self._uc.mem_read(arg_addr, 8)
            return struct.unpack("<Q", data)[0]
        else:
            raise Exception("not implemented!")

    def __setitem__(self, index, value):
        if not self._x64:
            raise Exception("not implemented!")
        regs = self._regs
        if index == 0:
            regs.rcx = value
        elif index == 1:
            regs.rdx = value
        elif index == 2:
            regs.r8 = value
        elif index == 3:
            regs.r9 = value
        else:
            raise Exception("not implemented!")


class Dumpulator(Architecture):
    def __init__(self, minidump_file, *, trace=False, quiet=False, thread_id=None):
        self._quiet = quiet

        # Load the minidump
        self._minidump = MinidumpFile.parse(minidump_file)
        if thread_id is None and self._minidump.exception is not None:
            thread_id = self._minidump.exception.exception_records[0].ThreadId
        if thread_id is None:
            thread = self._minidump.threads.threads[0]
        else:
            thread = self._find_thread(thread_id)

        super().__init__(type(thread.ContextObject) is not WOW64_CONTEXT)
        self.addr_mask = 0xFFFFFFFFFFFFFFFF if self._x64 else 0xFFFFFFFF

        if trace:
            self.trace = open(minidump_file + ".trace", "w")
        else:
            self.trace = None

        self.last_module: Optional[MinidumpModule] = None

        mode = UC_MODE_64 if self._x64 else UC_MODE_32
        self._uc = Uc(UC_ARCH_X86, mode)

        mode = CS_MODE_64 if self._x64 else CS_MODE_32
        self.cs = Cs(CS_ARCH_X86, mode)
        self.cs.detail = True

        self.regs = Registers(self._uc, self._x64)
        self.args = Arguments(self._uc, self.regs, self._x64)
        self._allocate_base = None
        self._allocate_size = 1024 * 1024 * 10  # NOTE: 10 megs
        self._allocate_ptr = None
        self._setup_emulator(thread)
        self.exit_code = None
        self.syscalls = []
        self._setup_syscalls()
        self.exports = self._setup_exports()

    def _find_thread(self, thread_id):
        for i in range(0, len(self._minidump.threads.threads)):
            thread = self._minidump.threads.threads[i]
            if thread.ThreadId == thread_id:
                return thread
        raise Exception(f"Thread 0x{thread_id:x} ({thread_id}) not found!")

    def info(self, message: str):
        if not self._quiet:
            print(message)

    def error(self, message: str):
        print(message)

    # Source: https://github.com/mandiant/speakeasy/blob/767edd2272510a5badbab89c5f35d43a94041378/speakeasy/windows/winemu.py#L533
    def _setup_gdt(self, teb_addr):
        """
        Set up the GDT so we can access segment registers correctly
        This will be done a little differently depending on architecture
        """

        GDT_SIZE = 0x1000
        PAGE_SIZE = 0x1000
        ENTRY_SIZE = 0x8
        num_gdt_entries = 31
        gdt_addr = 0x3000

        # For a detailed explaination of whats happening here, see:
        # https://wiki.osdev.org/Global_Descriptor_Table
        # We need to init the GDT so that shellcode can accurately access
        # segment registers which is needed for TEB access in user mode

        def _make_entry(index, base, access, limit=0xFFFFF000, flags=0x4):
            access |= (GDT_ACCESS_BITS.PresentBit | GDT_ACCESS_BITS.DirectionConformingBit)
            entry = 0xFFFF & limit
            entry |= (0xFFFFFF & base) << 16
            entry |= (0xFF & access) << 40
            entry |= (0xFF & (limit >> 16)) << 48
            entry |= (0xFF & flags) << 52
            entry |= (0xFF & (base >> 24)) << 56
            entry = entry.to_bytes(8, 'little')

            offset = index * ENTRY_SIZE
            self.write(gdt_addr + offset, entry)

        def _create_selector(index, flags):
            return flags | (index << 3)

        self._uc.mem_map(gdt_addr, GDT_SIZE)

        access = (GDT_ACCESS_BITS.Data | GDT_ACCESS_BITS.DataWritable |
                  GDT_ACCESS_BITS.Ring3)
        _make_entry(16, 0, access)

        access = (GDT_ACCESS_BITS.Code | GDT_ACCESS_BITS.CodeReadable |
                  GDT_ACCESS_BITS.Ring3)
        _make_entry(17, 0, access)

        access = (GDT_ACCESS_BITS.Data | GDT_ACCESS_BITS.DataWritable |
                  GDT_ACCESS_BITS.Ring0)
        _make_entry(18, 0, access)

        # WIP: Wow64 transition
        # See: https://github.com/unicorn-engine/unicorn/issues/626#issuecomment-242826990
        access = (GDT_ACCESS_BITS.Code | GDT_ACCESS_BITS.CodeReadable |
                  GDT_ACCESS_BITS.Ring3)
        _make_entry(6, 0, access, flags=0x4 | 0x2)
        # print(f"wow64: {_create_selector(6, GDT_FLAGS.Ring3):0x}")

        self.regs.gdtr = (0, gdt_addr, num_gdt_entries * ENTRY_SIZE - 1, 0x0)
        selector = _create_selector(16, GDT_FLAGS.Ring3)
        self.regs.ds = selector
        selector = _create_selector(17, GDT_FLAGS.Ring3)
        self.regs.cs = selector
        selector = _create_selector(18, GDT_FLAGS.Ring0)
        self.regs.ss = selector

        if not self._x64:
            # FS segment needed for PEB access at fs:[0x30]

            access = (GDT_ACCESS_BITS.Data | GDT_ACCESS_BITS.DataWritable |
                      GDT_ACCESS_BITS.Ring3)
            _make_entry(19, teb_addr, access)

            selector = _create_selector(19, GDT_FLAGS.Ring3)
            self.regs.fs = selector

        else:
            # GS Segment needed for PEB access at gs:[0x60]

            access = (GDT_ACCESS_BITS.Data | GDT_ACCESS_BITS.DataWritable |
                      GDT_ACCESS_BITS.Ring3)
            _make_entry(15, teb_addr, access, limit=PAGE_SIZE)

            selector = _create_selector(15, GDT_FLAGS.Ring3)
            self.regs.gs = selector

    def _setup_emulator(self, thread):
        # set up hooks
        self._uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_READ_PROT | UC_HOOK_MEM_WRITE_PROT | UC_HOOK_MEM_FETCH_PROT, _hook_mem, user_data=self)
        #self._uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, _hook_mem, user_data=self)
        if self.trace:
            self._uc.hook_add(UC_HOOK_CODE, _hook_code, user_data=self)
        #self._uc.hook_add(UC_HOOK_MEM_READ_INVALID, self._hook_mem, user_data=None)
        #self._uc.hook_add(UC_HOOK_MEM_WRITE_INVALID, self._hook_mem, user_data=None)
        self._uc.hook_add(UC_HOOK_INSN, _hook_syscall, user_data=self, arg1=UC_X86_INS_SYSCALL)
        self._uc.hook_add(UC_HOOK_INSN, _hook_syscall, user_data=self, arg1=UC_X86_INS_SYSENTER)
        self._uc.hook_add(UC_HOOK_INTR, _hook_interrupt, user_data=self)
        self._uc.hook_add(UC_HOOK_INSN_INVALID, _hook_invalid, user_data=self)

        # map in codecave
        self._uc.mem_map(CAVE_ADDR, CAVE_SIZE)
        self._uc.mem_write(CAVE_ADDR, b"\xCC" * CAVE_SIZE)

        info: MinidumpMemoryInfo
        for info in self._minidump.memory_info.infos:
            emu_addr = info.BaseAddress & self.addr_mask
            if info.State == MemoryState.MEM_COMMIT:
                self.info(f"mapped base: 0x{emu_addr:x}, size: 0x{info.RegionSize:x}, protect: {info.Protect}")
                self._uc.mem_map(emu_addr, info.RegionSize, map_unicorn_perms(info.Protect))
            elif info.State == MemoryState.MEM_FREE and emu_addr > 0x10000 and info.RegionSize >= self._allocate_size:
                self._allocate_base = emu_addr

        memory = self._minidump.get_reader().get_buffered_reader()
        seg: MinidumpMemorySegment
        for seg in self._minidump.memory_segments_64.memory_segments:
            emu_addr = seg.start_virtual_address & self.addr_mask
            self.info(f"initialize base: 0x{emu_addr:x}, size: 0x{seg.size:x}")
            memory.move(seg.start_virtual_address)
            assert memory.current_position == seg.start_virtual_address
            data = memory.read(seg.size)
            self._uc.mem_write(emu_addr, data)

        if self._x64:
            context: CONTEXT = thread.ContextObject
            self.regs.mxcsr = context.MxCsr
            self.regs.eflags = context.EFlags
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
            context: WOW64_CONTEXT = thread.ContextObject
            self.regs.eflags = context.EFlags
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

        # Remove the trap flag
        self.regs.eflags &= ~0x100

        # Set up TEB
        self.teb = thread.Teb & 0xFFFFFFFFFFFFF000
        self._setup_gdt(self.teb)
        self.regs.gs_base = self.teb

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

    def _setup_exports(self):
        exports = {}
        for module in self._minidump.modules.modules:
            module_name = module.name.split('\\')[-1].lower()
            self.info(f"{module_name} 0x{module.baseaddress:x}[0x{module.size:x}]")
            for export in self._parse_module_exports(module):
                if export.name:
                    name = export.name.decode("utf-8")
                else:
                    name = f"#{export.ordinal}"
                exports[module.baseaddress + export.address] = f"{module_name}:{name}"
        return exports

    def _find_module(self, name) -> MinidumpModule:
        module: MinidumpModule
        for module in self._minidump.modules.modules:
            filename = module.name.split('\\')[-1].lower()
            if filename == name.lower():
                return module
        raise Exception(f"Module '{name}' not found")

    def find_module_by_addr(self, address) -> Optional[MinidumpModule]:
        module: MinidumpModule
        for module in self._minidump.modules.modules:
            if module.baseaddress <= address < module.baseaddress + module.size:
                return module
        return None

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

    def _setup_syscalls(self):
        # Load the ntdll module from memory
        ntdll = self._find_module("ntdll.dll")
        syscalls = []
        for export in self._parse_module_exports(ntdll):
            if export.name and export.name.startswith(b"Zw"):
                syscalls.append((export.address, export.name.decode("utf-8")))
            elif export.name == b"Wow64Transition":
                addr = ntdll.baseaddress + export.address
                patch_addr = self.read_ptr(addr)
                self.info(f"Patching Wow64Transition: {addr:0x} -> {patch_addr:0x}")
                # See: https://opcode0x90.wordpress.com/2007/05/18/kifastsystemcall-hook/
                # mov edx, esp; sysenter; ret
                KiFastSystemCall = b"\x8B\xD4\x0F\x34\xC3"
                self.write(patch_addr, KiFastSystemCall)

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

    def protect(self, addr, size, protect):
        perms = map_unicorn_perms(protect)
        self._uc.mem_protect(addr, size, perms)

    def call(self, addr, args: List[int]=[], regs: dict={}, count=0):
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
        self.push(CAVE_ADDR)
        # start emulation
        self.start(addr, end=CAVE_ADDR, count=count)
        return self.regs.cax

    def allocate(self, size):
        if not self._allocate_ptr:
            self._uc.mem_map(self._allocate_base, self._allocate_size)
            self._allocate_ptr = self._allocate_base

        ptr = self._allocate_ptr + size
        if ptr > self._allocate_base + self._allocate_size:
            raise Exception("not enough room to allocate!")
        self._allocate_ptr = ptr
        return ptr

    def start(self, begin, end=0xffffffffffffffff, count=0):
        try:
            self._uc.emu_start(begin, until=end, count=count)
            self.info(f'emulation finished, cip = {self.regs.cip:0x}')
            if self.exit_code is not None:
                self.info(f"exit code: {self.exit_code}")
        except UcError as err:
            self.error(f'error: {err}, cip = {self.regs.cip:0x}')

    def stop(self, exit_code=None):
        self.exit_code = int(exit_code)
        self._uc.emu_stop()

    def NtCurrentProcess(self):
        return 0xFFFFFFFFFFFFFFFF if self._x64 else 0xFFFFFFFF

    def NtCurrentThread(self):
        return 0xFFFFFFFFFFFFFFFE if self._x64 else 0xFFFFFFFE


def _hook_mem(uc: Uc, access, address, size, value, dp: Dumpulator):
    if access == UC_MEM_READ_UNMAPPED:
        dp.error(f"unmapped read from {address:0x}[{size:0x}], cip = {dp.regs.cip:0x}")
    elif access == UC_MEM_WRITE_UNMAPPED:
        dp.error(f"unmapped write to {address:0x}[{size:0x}] = {value:0x}, cip = {dp.regs.cip:0x}")

    elif access == UC_MEM_FETCH_UNMAPPED:
        dp.error(f"unmapped fetch of {address:0x}[{size:0x}] = {value:0x}, cip = {dp.regs.cip:0x}")
    return False

def _get_regs(instr):
    regs = OrderedDict()
    for op in instr.operands:
        if op.type == CS_OP_REG:
            regs[instr.reg_name(op.value.reg)] = None
        elif op.type == CS_OP_MEM:
            if op.value.mem.base != 0:
                regs[instr.reg_name(op.value.mem.base)] = None
            if op.value.mem.index != 0:
                regs[instr.reg_name(op.value.mem.index)] = None
    for reg in instr.regs_read:
        regs[instr.reg_name(reg)] = None
    for reg in instr.regs_write:
        regs[instr.reg_name(reg)] = None
    return regs

def _hook_code(uc: Uc, address, size, dp: Dumpulator):
    code = dp.read(address, size)
    instr = next(dp.cs.disasm(code, address, 1))
    address_name = dp.exports.get(address, "")

    module = ""
    if dp.last_module and dp.last_module.baseaddress <= address < dp.last_module.baseaddress + dp.last_module.size:
        # same module again
        pass
    else:
        # new module
        dp.last_module = dp.find_module_by_addr(address)
        if dp.last_module:
            module = dp.last_module.name.split("\\")[-1].lower()

    if address_name:
        address_name = " " + address_name
    elif module:
        address_name = " " + module

    line = f"0x{address:x}{address_name}|{instr.mnemonic}"
    if instr.op_str:
        line += " "
        line += instr.op_str
    for reg in _get_regs(instr):
        line += f"|{reg}=0x{dp.regs.__getattr__(reg):x}"
    line += "\n"
    dp.trace.write(line)
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
    dp.error(f"interrupt {number}, cip = {dp.regs.cip:0x}")
    uc.emu_stop()


def _hook_syscall(uc: Uc, dp: Dumpulator):
    index = dp.regs.cax & 0xffff
    if index < len(dp.syscalls):
        name, cb, argcount = dp.syscalls[index]
        if cb:
            argspec = inspect.getfullargspec(cb)
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
                        argvalue = argtype(dp.args[i])
                    except KeyError as x:
                        raise Exception(f"Unknown enum value {dp.args[i]} for {type(argtype)}")
                else:
                    argvalue = argtype(argvalue)
                args.append(argvalue)

                comma = ","
                if i + 1 == argcount:
                    comma = ""

                dp.info(f"    {_arg_type_string(argvalue)} {argname} = {_arg_to_string(argvalue)}{comma}")
            dp.info(")")
            try:
                status = cb(dp, *args)
                dp.info(f"status = {status:x}")
                dp.regs.cax = status
                dp.regs.ccx = dp.regs.cip + 2
            except Exception as exc:
                sys.stderr = sys.stdout
                traceback.print_exception(type(exc), exc, exc.__traceback__)
                dp.error(f"Exception thrown during syscall implementation, stopping emulation!")
                uc.emu_stop()
        else:
            dp.error(f"syscall index: {index:0x} -> {name} not implemented!")
            uc.emu_stop()
    else:
        dp.error(f"syscall index {index:0x} out of range")
        uc.emu_stop()

def _hook_invalid(uc: Uc, address, dp: Dumpulator):
    dp.error(f"invalid instruction at {address:0x}")
    return False
