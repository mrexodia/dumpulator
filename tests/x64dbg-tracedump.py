# Based on: https://github.com/teemu-l/execution-trace-viewer (MIT)
# Licensed under MIT (not BSL)

import sys
import json
from capstone import *
from capstone.x86_const import *
from operator import attrgetter
from collections import OrderedDict

class TraceData:
    """TraceData class.

    Class for storing execution trace and bookmarks.

    Attributes:
        filename (str): A trace file name.
        arch (str): CPU architecture.
        ip_reg (str): Name of instruction pointer register
        pointer_size (int): Pointer size (4 in x86, 8 in x64)
        regs (dict): Register names and indexes
        trace (list): A list of traced instructions, registers and memory accesses.
        bookmarks (list): A list of bookmarks.
    """

    def __init__(self):
        """Inits TraceData."""
        self.filename = ""
        self.arch = ""
        self.ip_reg = ""
        self.pointer_size = 0
        self.regs = {}
        self.trace = []
        self.bookmarks = []

    def clear(self):
        """Clears trace and all data"""
        self.trace = []
        self.bookmarks = []

    def get_trace(self):
        """Returns a full trace

        Returns:
            list: Trace
        """
        return self.trace

    def get_regs(self):
        """Returns dict of registers and their indexes

        Returns:
            dict: Regs
        """
        return self.regs

    def get_regs_and_values(self, row):
        """Returns dict of registers and their values

        Returns:
            dict: Register names and values
        """
        registers = {}
        try:
            reg_values = self.trace[row]["regs"]
            for reg_name, reg_index in self.regs.items():
                reg_value = reg_values[reg_index]
                registers[reg_name] = reg_value
        except IndexError:
            print(f"Error. Could not get regs from row {row}.")
            return {}
        return registers

    def get_reg_index(self, reg_name):
        """Returns a register index

        Args:
            reg_name (str): Register name
        Returns:
            int: Register index
        """
        try:
            index = self.regs[reg_name]
        except KeyError:
            print("Unknown register")
        return index

    def get_modified_regs(self, row):
        """Returns modfied regs

        Args:
            row (int): Trace row index
        Returns:
            list: List of register names
        """
        modified_regs = []
        reg_values = self.trace[row]["regs"]
        next_row = row + 1
        if next_row < len(self.trace):
            next_row_data = self.trace[next_row]
            for reg_name, reg_index in self.regs.items():
                reg_value = reg_values[reg_index]
                next_reg_value = next_row_data["regs"][reg_index]
                if next_reg_value != reg_value:
                    modified_regs.append(reg_name)
        return modified_regs

    def get_trace_rows(self, rows):
        """Returns a trace of given rows

        Args:
            rows (list): List of trace indexes
        Returns:
            list: Trace
        """
        trace = []
        try:
            trace = [self.trace[int(i)] for i in rows]
        except IndexError:
            print("Error. Could not get trace rows.")
        return trace

    def get_instruction_pointer_name(self):
        """Returns an instruction pointer name

        Returns:
            str: Instruction pointer name
        """
        if self.ip_reg:
            return self.ip_reg
        elif "eip" in self.regs:
            return "eip"
        elif "rip" in self.regs:
            return "rip"
        elif "ip" in self.regs:
            return "ip"
        elif "pc" in self.regs:
            return "pc"
        return ""

    def get_instruction_pointer(self, row):
        """Returns a value of instruction pointer of given row

        Args:
            row: A row index in trace
        Returns:
            int: Address of instruction
        """
        ip = 0
        ip_reg = self.get_instruction_pointer_name()
        try:
            reg_index = self.regs[ip_reg]
            ip = self.trace[row]["regs"][reg_index]
        except IndexError:
            print(f"Error. Could not get IP from row {row}")
        return ip

    def set_comment(self, row, comment):
        """Adds a comment to trace

        Args:
            row (int): Row index in trace
            comment (str): Comment text
        """
        try:
            self.trace[row]["comment"] = str(comment)
        except IndexError:
            print(f"Error. Could not set comment to row {row}")

    def add_bookmark(self, new_bookmark, replace=False):
        """Adds a new bookmark

        Args:
            new_bookmark (Bookmark): A new bookmark
            replace (bool): Replace an existing bookmark if found on same row?
                Defaults to False.
        """
        for i, bookmark in enumerate(self.bookmarks):
            if bookmark.startrow == new_bookmark.startrow:
                if replace:
                    self.bookmarks[i] = new_bookmark
                    print(f"Bookmark at {bookmark.startrow} replaced.")
                else:
                    print(f"Error: bookmark at {bookmark.startrow} already exists.")
                return
        self.bookmarks.append(new_bookmark)
        self.sort_bookmarks()

    def delete_bookmark(self, index):
        """Deletes a bookmark

        Args:
            index (int): Index on bookmark list
        Returns:
            bool: True if bookmark deleted, False otherwise
        """
        try:
            del self.bookmarks[index]
        except IndexError:
            print(f"Error. Could not delete a bookmark {index}")
            return False
        return True

    def sort_bookmarks(self):
        """Sorts bookmarks by startrow"""
        self.bookmarks.sort(key=attrgetter("startrow"))

    def get_bookmark_from_row(self, row):
        """Returns a bookmark for a given trace row.

        Args:
            row (int): Trace row index
        Returns:
            Bookmark: Returns A Bookmark if found, None otherwise.
        """
        return next(
            (
                bookmark
                for bookmark in self.bookmarks
                if bookmark.startrow <= row <= bookmark.endrow
            ),
            None,
        )

    def get_bookmarks(self):
        """Returns all bookmarks

        Returns:
            list: List of bookmarks
        """
        return self.bookmarks

    def set_bookmarks(self, bookmarks):
        """Sets bookmarks

        Args:
            bookmarks (list): Bookmarks
        """
        self.bookmarks = bookmarks

    def clear_bookmarks(self):
        """Clears bookmarks"""
        self.bookmarks = []

# registers for x64dbg traces
# if you want to see more regs, add them here (in correct order)
# check the order of regs from REGISTERCONTEXT:
# https://github.com/x64dbg/x64dbg/blob/development/src/bridge/bridgemain.h#L723
X32_REGS = [
    "eax",
    "ecx",
    "edx",
    "ebx",
    "esp",
    "ebp",
    "esi",
    "edi",
    "eip",
    "eflags",
    "seg:gs,fs",
    "seg:es,ds",
    "seg:cs,ss",
    "dr0",
    "dr1",
    "dr2",
    "dr3",
    "dr6",
    "dr7",
]
X64_REGS = [
    "rax",
    "rcx",
    "rdx",
    "rbx",
    "rsp",
    "rbp",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "rip",
    "eflags",
    "seg:gs,fs,es,ds",
    "seg:cs,ss",
    "dr0",
    "dr1",
    "dr2",
    "dr3",
    "dr6",
    "dr7",
]

def _get_regs(instr, include_write=False):
    regs = OrderedDict()
    if instr.id != X86_INS_NOP:
        operands = instr.operands
        for i in range(len(operands)):
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

# TODO: this function uses a lot of ram, modify it do allow accessing the trace as a stream
def open_x64dbg_trace(filename, tracef):
    """Opens x64dbg trace file

    Args:
        filename: name of trace file
        tracef: file handle of txt trace
    Returns:
        TraceData object
    """
    with open(filename, "rb") as f:
        trace_data = TraceData()
        trace_data.filename = filename

        # check first 4 bytes
        magic = f.read(4)
        if magic != b"TRAC":
            raise ValueError("Error, wrong file format.")

        json_length_bytes = f.read(4)
        json_length = int.from_bytes(json_length_bytes, "little")

        # read JSON blob
        json_blob = f.read(json_length)
        json_str = str(json_blob, "utf-8")
        arch = json.loads(json_str)["arch"]

        reg_masks = {}
        reg_indexes = {}
        if arch == "x64":
            regs = X64_REGS
            ip_reg = "rip"
            capstone_mode = CS_MODE_64
            pointer_size = 8  # qword
        else:
            regs = X32_REGS
            ip_reg = "eip"
            capstone_mode = CS_MODE_32
            pointer_size = 4  # dword

        for i, reg in enumerate(regs):
            if reg.startswith("seg:"):
                for j, seg in enumerate(reg[4:].split(',')):
                    reg_indexes[seg] = i
                    reg_masks[seg] = 0xFFFF << (16 * j)
            else:
                reg_indexes[reg] = i
                reg_masks[reg] = 0xFFFFFFFFFFFFFFFF >> (64 - pointer_size * 8)
        reg_indexes["rflags"] = reg_indexes["eflags"]
        reg_masks["rflags"] = reg_masks["eflags"]

        def add_reg(parent, child, mask):
            reg_indexes[child] = reg_indexes[parent]
            reg_masks[child] = mask

        if pointer_size == 8:
            for reg in X32_REGS[:9]:
                add_reg(f"r{reg[1:]}", reg, 0xFFFFFFFF)

            add_reg("r8", "r8d", 0xFFFFFFFF)
            add_reg("r9", "r9d", 0xFFFFFFFF)
            add_reg("r10", "r10d", 0xFFFFFFFF)
            add_reg("r11", "r11d", 0xFFFFFFFF)
            add_reg("r12", "r12d", 0xFFFFFFFF)
            add_reg("r13", "r13d", 0xFFFFFFFF)
            add_reg("r14", "r14d", 0xFFFFFFFF)
            add_reg("r15", "r15d", 0xFFFFFFFF)

            add_reg("r8", "r8w", 0xFFFF)
            add_reg("r9", "r9w", 0xFFFF)
            add_reg("r10", "r10w", 0xFFFF)
            add_reg("r11", "r11w", 0xFFFF)
            add_reg("r12", "r12w", 0xFFFF)
            add_reg("r13", "r13w", 0xFFFF)
            add_reg("r14", "r14w", 0xFFFF)
            add_reg("r15", "r15w", 0xFFFF)

            add_reg("r8", "r8b", 0xFF)
            add_reg("r9", "r9b", 0xFF)
            add_reg("r10", "r10b", 0xFF)
            add_reg("r11", "r11b", 0xFF)
            add_reg("r12", "r12b", 0xFF)
            add_reg("r13", "r13b", 0xFF)
            add_reg("r14", "r14b", 0xFF)
            add_reg("r15", "r15b", 0xFF)

            add_reg("rsi", "sil", 0xFF)
            add_reg("rdi", "dil", 0xFF)
            add_reg("rbp", "bpl", 0xFF)
            add_reg("rsp", "spl", 0xFF)

        for reg in X32_REGS[:9]:
            add_reg(reg, reg[1:], 0xFFFF)

        add_reg("eax", "al", 0xFF)
        add_reg("eax", "ah", 0xFF00)
        add_reg("ebx", "bl", 0xFF)
        add_reg("ebx", "bh", 0xFF00)
        add_reg("ecx", "cl", 0xFF)
        add_reg("ecx", "ch", 0xFF00)
        add_reg("edx", "dl", 0xFF)
        add_reg("edx", "dh", 0xFF00)

        trace_data.arch = arch
        trace_data.ip_reg = ip_reg
        trace_data.regs = reg_indexes
        trace_data.pointer_size = pointer_size

        md = Cs(CS_ARCH_X86, capstone_mode)
        md.detail = True
        reg_values = [None] * len(regs)
        trace = []
        row_id = 0
        while f.read(1) == b"\x00":
            register_changes = int.from_bytes(f.read(1), "little")
            memory_accesses = int.from_bytes(f.read(1), "little")
            flags_and_opcode_size = int.from_bytes(f.read(1), "little")  # Bitfield
            thread_id_bit = (flags_and_opcode_size >> 7) & 1  # msb
            opcode_size = flags_and_opcode_size & 15  # 4 lsbs

            if thread_id_bit > 0:
                thread_id = int.from_bytes(f.read(4), "little")

            opcodes = f.read(opcode_size)

            register_change_position = []
            for _ in range(register_changes):
                register_change_position.append(int.from_bytes(f.read(1), "little"))

            register_change_new_data = []
            for _ in range(register_changes):
                register_change_new_data.append(
                    int.from_bytes(f.read(pointer_size), "little")
                )

            memory_access_flags = []
            for _ in range(memory_accesses):
                memory_access_flags.append(int.from_bytes(f.read(1), "little"))

            memory_access_addresses = []
            for _ in range(memory_accesses):
                memory_access_addresses.append(
                    int.from_bytes(f.read(pointer_size), "little")
                )

            memory_access_old_data = []
            for _ in range(memory_accesses):
                memory_access_old_data.append(
                    int.from_bytes(f.read(pointer_size), "little")
                )

            memory_access_new_data = []
            for i in range(memory_accesses):
                if memory_access_flags[i] & 1 == 0:
                    memory_access_new_data.append(
                        int.from_bytes(f.read(pointer_size), "little")
                    )

            reg_id = 0
            regchanges = ""
            for i, change in enumerate(register_change_position):
                reg_id += change
                if reg_id + i < len(regs):
                    reg_values[reg_id + i] = register_change_new_data[i]
                if reg_id + i < len(regs) and row_id > 0:
                    reg_name = regs[reg_id + i]
                    if reg_name is not ip_reg:
                        old_value = trace[-1]["regs"][reg_id + i]
                        new_value = register_change_new_data[i]
                        if old_value != new_value:
                            regchanges += f"{reg_name}: {hex(new_value)} "
                            if 0x7F > new_value > 0x1F:
                                regchanges += f"'{chr(new_value)}' "

            # disassemble
            ip = reg_values[reg_indexes[ip_reg]]
            for _address, _size, mnemonic, op_str in md.disasm_lite(opcodes, ip):
                disasm = mnemonic
                if op_str:
                    disasm += f" {op_str}"

            def get_reg(name):
                if len(name) == 2 and name[1] == 's':
                    print(f"{name} moment")
                index = reg_indexes[name]
                mask = reg_masks[name]
                val = reg_values[index]
                # Shifts are encoded in the mask
                while (mask & 0xFF) == 0:
                    mask >>= 8
                    val >>= 8
                return val & mask

            # (somewhat) matches format in dumpulator.py _hook_code
            instr = next(md.disasm(opcodes, ip, 1))
            address = ip
            address_name = ""
            line = f"0x{address:x}{address_name}|{instr.mnemonic}"
            if instr.op_str:
                line += " "
                line += instr.op_str
            for reg in _get_regs(instr):
                line += f"|{reg}=0x{get_reg(reg):x}" if reg in reg_indexes else f"|{reg}=0x???"
            line += "\n"
            tracef.write(line)

            mems = []
            mem = {}
            new_data_counter = 0
            for i in range(memory_accesses):
                flag = memory_access_flags[i]
                value = memory_access_old_data[i]
                mem["access"] = "READ"
                if flag & 1 == 0:
                    value = memory_access_new_data[new_data_counter]
                    mem["access"] = "WRITE"
                    new_data_counter += 1
                mem["addr"] = memory_access_addresses[i]

                # fix value (x64dbg saves all values as qwords)
                if "qword" in disasm:
                    pass
                elif "dword" in disasm:
                    value &= 0xFFFFFFFF
                elif "word" in disasm:
                    value &= 0xFFFF
                elif "byte" in disasm:
                    value &= 0xFF
                mem["value"] = value
                mems.append(mem.copy())

            if regchanges:
                trace[-1]["regchanges"] = regchanges

            trace_row = {}
            trace_row["id"] = row_id
            trace_row["ip"] = ip
            trace_row["disasm"] = disasm
            trace_row["regs"] = reg_values.copy()
            trace_row["opcodes"] = opcodes.hex()
            trace_row["mem"] = mems.copy()
            # trace_row["comment"] = ""
            trace.append(trace_row)
            row_id += 1

        trace_data.trace = trace
        return trace_data


def main():
    if len(sys.argv) < 2:
        print("Usage: x64dbg-tracedump my.trace64")
        return
    trace_file = sys.argv[1]
    with open(f"{trace_file}.txt", "w") as tracef:
        data = open_x64dbg_trace(trace_file, tracef)

if __name__ == '__main__':
    main()
