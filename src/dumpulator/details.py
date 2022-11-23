import struct
from collections import namedtuple
from typing import List

from unicorn import *
from unicorn.x86_const import *

from dumpulator.memory import MemoryProtect

def map_unicorn_perms(protect: MemoryProtect):
    if isinstance(protect, int):
        protect = MemoryProtect(protect)
    assert isinstance(protect, MemoryProtect)
    baseprotect = protect & ~(MemoryProtect.PAGE_WRITECOMBINE | MemoryProtect.PAGE_NOCACHE | MemoryProtect.PAGE_GUARD)
    mapping = {
        MemoryProtect.PAGE_EXECUTE: UC_PROT_EXEC | UC_PROT_READ,
        MemoryProtect.PAGE_EXECUTE_READ: UC_PROT_EXEC | UC_PROT_READ,
        MemoryProtect.PAGE_EXECUTE_READWRITE: UC_PROT_ALL,
        MemoryProtect.PAGE_EXECUTE_WRITECOPY: UC_PROT_ALL,
        MemoryProtect.PAGE_NOACCESS: UC_PROT_NONE,
        MemoryProtect.PAGE_READONLY: UC_PROT_READ,
        MemoryProtect.PAGE_READWRITE: UC_PROT_READ | UC_PROT_WRITE,
        MemoryProtect.PAGE_WRITECOPY: UC_PROT_READ | UC_PROT_WRITE,
    }
    perms = mapping[baseprotect]
    if protect & MemoryProtect.PAGE_GUARD:
        perms = UC_PROT_NONE
    return perms


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
        self._flagposdict = {
            "cf": 0,
            "pf": 1,
            "af": 3,
            "zf": 5,
            "sf": 6,
            "tf": 7,
            "if": 8,
            "df": 9,
            "of": 10,
            "iopl": 12,
            "nt": 13,
            "rf": 15,
            "vm": 16,
            "ac": 17,
            "vif": 18,
            "vip": 19,
            "id": 20
        }

    def _resolve_reg(self, regname):
        uc_reg = self._regmap.get(regname, None)
        if uc_reg is None:
            raise Exception(f"Unknown register '{regname}'")
        #if not self._x64 and regname.startswith("r"):
        #    raise Exception(f"Register {regname} is not available in 32-bit mode")
        return uc_reg

    def __getattr__(self, name: str):
        if name in self._flagposdict:
            eflags = self._uc.reg_read(self._resolve_reg("eflags"))
            return (eflags >> self._flagposdict[name]) & 1
        return self._uc.reg_read(self._resolve_reg(name))

    def __setattr__(self, name: str, value):
        if name.startswith("_"):
            object.__setattr__(self, name, value)
        elif name in self._flagposdict: # For setting specific flags
            resolved_reg = self._resolve_reg("eflags")
            holder = self._uc.reg_read(resolved_reg)
            if value == 0:
                repl_value = holder & ~(1 << self._flagposdict[name])
                self._uc.reg_write(resolved_reg, repl_value)
            elif value == 1:
                repl_value = holder | (1 << self._flagposdict[name])
                self._uc.reg_write(resolved_reg, repl_value)
            else:
                raise Exception(f"Attempted to improperly set flag '{name}'")
        else:
            self._uc.reg_write(self._resolve_reg(name), value)

    # value = dp.regs[myname]
    def __getitem__(self, name: str):
        return self.__getattr__(name)

    # dp.regs[myname] = value
    def __setitem__(self, name: str, value):
        return self.__setattr__(name, value)

    def __contains__(self, name: str):
        try:
            self._resolve_reg(name)
            return True
        except Exception:
            return False


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

"""
These values are copied from a live Windows 10 VM.

References:
- https://wiki.osdev.org/Global_Descriptor_Table
- daax and lauree for helping me understand this stuff

Selector 0x10 (index 2)
UInt64: 0x00209b0000000000 => kernel CS
  Base: 0x0000000000000000
 Limit: 0x0000000000000000
  Type: 11 <- code execute+read+access
     S: 1
   DPL: 0 <- ring0
     P: 1
     L: 1 <- 64-bit
    DB: 0

Selector 0x18 (index 3) => kernel SS
UInt64: 0x0040930000000000
  Base: 0x0000000000000000
 Limit: 0x0000000000000000
  Type: 3 <- data read+write+access
     S: 1
   DPL: 0 <- ring0
     P: 1
     L: 0
    DB: 1 <- 32-bit

Selector 0x20 (index 4) => user wow64 CS
UInt64: 0x00cffb000000ffff
  Base: 0x0000000000000000
 Limit: 0x00000000ffffffff
  Type: 11 <- code execute+read+access
     S: 1
   DPL: 3 <- ring3
     P: 1
     L: 0
    DB: 1 <- 32-bit

Selector 0x28 (index 5) => kernel DS,ES,GS + user SS
UInt64: 0x00cff3000000ffff
  Base: 0x0000000000000000
 Limit: 0x00000000ffffffff
  Type: 3 <- data read+write+access
     S: 1
   DPL: 3 <- ring3
     P: 1
     L: 0
    DB: 1 <- 32-bit

Selector 0x30 (index 6) => user CS
UInt64: 0x0020fb0000000000
  Base: 0x0000000000000000
 Limit: 0x0000000000000000
  Type: 11 <- code execute+read+access
     S: 1
   DPL: 3 <- ring3
     P: 1
     L: 1 <- 64-bit
    DB: 0

Selector 0x40 (index 8) => TSS
UInt64: 0x6d008b9630000067
  Base: 0xfffff8076d963000
 Limit: 0x0000000000000067
  Type: 11 <- 64-bit TSS (Busy)
     S: 0 <- system segment
   DPL: 0 <- ring0
     P: 1
     L: 0
    DB: 0

Selector 0x50 (index 10) => kernel FS
UInt64: 0x0040f30000003c00
  Base: 0x0000000000000000
 Limit: 0x0000000000003c00
  Type: 3 <- data read+write+access
     S: 1
   DPL: 3 <- ring3
     P: 1
     L: 0
    DB: 1 <- 32-bit
"""
windows_gdt = [
    0x0000000000000000,  # NULL
    0x0000000000000000,
    0x00209b0000000000,  # kernel CS
    0x0040930000000000,  # kernel SS
    0x00cffb000000ffff,  # user wow64 CS
    0x00cff3000000ffff,  # kernel DS,ES,GS + user SS
    0x0020fb0000000000,  # user CS
    0x0000000000000000,
    0x6d008b9630000067,  # TSS (base: 0xfffff8076d963000)
    0x00000000fffff807,
    0x0040f30000003c00,  # kernel FS
]

SegmentRegisters = namedtuple("SegmentRegisters", ["cs", "ss", "ds", "es", "fs", "gs"])

windows_kernel_segment = SegmentRegisters(0x10, 0x18, 0x2B, 0x2B, 0x53, 0x2B)
windows_user_segment = SegmentRegisters(0x33, 0x2B, 0x2B, 0x2B, 0x53, 0x2B)
windows_wow64_segment = SegmentRegisters(0x23, 0x2B, 0x2B, 0x2B, 0x53, 0x2B)

# Reference: https://wiki.osdev.org/Exceptions
interrupt_names = [
    "#DE, Division by Zero",
    "#DB, Debug",
    "Non-maskable Interrupt",
    "#BP, Breakpoint",
    "#OF, Overflow",
    "#BR, Bound Range Exceeded",
    "#UD, Invalid Opcode",
    "#NM, Device Not Available",
    "#DF, Double Fault",
    "Coprocessor Segment Overrun",
    "#TS, Invalid TSS",
    "#NP, Segment Not Present",
    "#SS, Stack-Segment Fault",
    "#GP, General Protection Fault",
    "#PF, Page Fault",
    "Reserved",
    "#MF, x87 Floating-Point Exception",
    "#AC, Alignment Check",
    "#MC, Machine Check",
    "SIMD Floating-Point Exception, #XM/#XF",
    "#VE, Virtualization Exception",
    "#CP, Control Protection Exception",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "#HV, Hypervisor Injection Exception",
    "#VC, VMM Communication Exception",
    "#SX, Security Exception",
    "Reserved"
]
assert len(interrupt_names) == 32

def format_table(table: List[List[str]]):
    result = ""
    header = table[0]
    lengths = [0] * len(header)
    for row in table:
        for index, col in enumerate(row):
            lengths[index] = max(lengths[index], len(col))
    for row in table:
        if len(result) > 0:
            result += "\n"
        line = ""
        for index, col in enumerate(row):
            if index > 0:
                line += " "
            line += f"{col:>{lengths[index]}}"
        result += line.rstrip()
    return result