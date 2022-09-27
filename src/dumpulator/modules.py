from .dumpulator import Dumpulator
from minidump.streams.ModuleListStream import MinidumpModule
from pefile import *
from unicorn import *
from .handles import *


class Peb:
    def __init__(self, dp: Dumpulator):
        # https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
        # Handle PEB
        # Retrieve console handle
        if dp._x64:
            # https://www.vergiliusproject.com/kernels/x64/Windows%2011/21H2%20(RTM)/_TEB
            self.peb = dp.read_ptr(dp.teb + 0x60)
            # https://www.vergiliusproject.com/kernels/x64/Windows%2011/21H2%20(RTM)/_PEB
            self.image_base_address = dp.read_ptr(self.peb + 0x10)
            self.process_parameters = dp.read_ptr(self.peb + 0x20)
            # https://www.vergiliusproject.com/kernels/x64/Windows%2011/21H2%20(RTM)/_RTL_USER_PROCESS_PARAMETERS
            self.console_handle = dp.read_ptr(self.process_parameters + 0x10)
            self.stdin_handle = dp.read_ptr(self.process_parameters + 0x20)
            self.stdout_handle = dp.read_ptr(self.process_parameters + 0x28)
            self.stderr_handle = dp.read_ptr(self.process_parameters + 0x30)
        else:
            # https://www.vergiliusproject.com/kernels/x86/Windows%2010/2110%2021H2%20(November%202021%20Update)/_TEB
            self.peb = dp.read_ptr(dp.teb + 0x30)
            # https://www.vergiliusproject.com/kernels/x86/Windows%2010/2110%2021H2%20(November%202021%20Update)/_PEB
            self.image_base_address = dp.read_ptr(self.peb + 0x08)
            self.process_parameters = dp.read_ptr(self.peb + 0x10)
            # https://www.vergiliusproject.com/kernels/x86/Windows%2010/2110%2021H2%20(November%202021%20Update)/_RTL_USER_PROCESS_PARAMETERS
            self.console_handle = dp.read_ptr(self.process_parameters + 0x10)
            self.stdin_handle = dp.read_ptr(self.process_parameters + 0x18)
            self.stdout_handle = dp.read_ptr(self.process_parameters + 0x1c)
            self.stderr_handle = dp.read_ptr(self.process_parameters + 0x20)

            dp.info(f"TEB: 0x{dp.teb:x}, PEB: 0x{self.peb:x}")
            dp.info(f"  ConsoleHandle: 0x{self.console_handle:x}")
            dp.info(f"  StandardInput: 0x{self.stdin_handle:x}")
            dp.info(f"  StandardOutput: 0x{self.stdout_handle:x}")
            dp.info(f"  StandardError: 0x{self.stderr_handle:x}")


class Function:
    def __init__(self, name: str, address: int, va: int,):
        self.name = name
        self.va = va
        self.address = address

    def __lt__(self, export: 'Function'):
        return self.va < export.va

    def __gt__(self, export: 'Function'):
        return self.va < export.va

    def __eq__(self, export: 'Function'):
        return self.va == export.va


class Module:
    def __init__(self, dp: Dumpulator, minidump_module: MinidumpModule):
        self._dp = dp
        self._minidump_module = minidump_module
        self.full_path = self._minidump_module.name
        self.name = self.full_path.split('\\')[-1].lower()
        self.base_address = self._minidump_module.baseaddress
        self.size = self._minidump_module.size
        self.end_address = self._minidump_module.endaddress
        self.version_info = self._minidump_module.versioninfo
        self.checksum = self._minidump_module.checksum
        self.time_stamp = self._minidump_module.timestamp
        self.pe = self.__parse_pe()
        self._functions = {}
        self.__parse_exports()  # adds exports to _functions dict

    # TODO: finish off the operator _functions to work with the funcs dict

    def __contains__(self, item):
        return item in self._functions

    def __iter__(self):
        return iter(self._functions.values())

    def __setitem__(self, key, value):
        self._functions[key] = value

    def __getitem__(self, key):
        assert key in self._functions
        return self._functions[key]

    def __delitem__(self, key):
        assert key in self._functions
        del self._functions[key]

    def contains_address(self, address: int) -> bool:
        return self.base_address <= address < self.end_address

    def __parse_pe(self):
        try:
            module_data = self._dp.read(self.base_address, self.size)
        except UcError:
            self._dp.error(f"Failed to read {self.name}'s module data")
            return None

        pe = PE(data=module_data, fast_load=True)
        # Hack to adjust pefile to accept in-memory modules
        for section in pe.sections:
            # Potentially interesting members: Misc_PhysicalAddress, Misc_VirtualSize, SizeOfRawData
            section.PointerToRawData = section.VirtualAddress
            section.PointerToRawData_adj = section.VirtualAddress
        return pe

    def __parse_exports(self):
        self.pe.parse_data_directories(directories=[DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            for export in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if export.name:
                    name = export.name.decode("utf-8")
                else:
                    name = f"#{export.ordinal}"
                self._functions[name] = Function(name, export.address, self.base_address + export.address)

    def find_function_name(self, address: int) -> str:
        for export in self._functions.values():
            if export.address == address:
                return f"{self.name}:{export.name}"
        return f"{self.name}:unknown_function"


class ModuleManager:
    def __init__(self, dp: Dumpulator):
        self.dp = dp
        self.peb = Peb(dp)
        self._modules = {}

        for dump_module in dp._minidump.modules.modules:
            module = Module(dp, dump_module)
            self._modules[module.name] = module
            dp.info(f"Parsed {module.name} 0x{module.base_address:x}[0x{module.size}]")

    def __contains__(self, item):
        return item in self._modules

    def __iter__(self):
        return iter(self._modules.values())

    def __setitem__(self, key, value):
        self._modules[key] = value

    def __getitem__(self, key):
        assert key in self._modules
        return self._modules[key]

    def __delitem__(self, key):
        assert key in self._modules
        del self._modules[key]

    def find_function_name(self, address: int) -> str:
        for name, module in self._modules.items():
            if address in module:
                return module.find_function_name(address)
        return "unknown_address"

    def find_module_by_address(self, address: int) -> Module:
        for module in self._modules.values():
            if module.contains_address(address):
                return module

    # TODO: map new module into ModuleManager
    def __map_module(self, file_data: bytes, file_name: str = "", requested_base: int = 0):
        print(f"Mapping module {file_name if file_name else '<unnamed>'}")
        pe = PE(name=None, data=file_data)
        image_size = pe.OPTIONAL_HEADER.SizeOfImage
        section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
        assert section_alignment == 0x1000
        if requested_base == 0:
            image_base = self.dp.allocate(image_size, True)
        else:
            image_base = requested_base
            self.dp._uc.mem_map(image_base, image_size)

        # TODO: map the header properly
        header = pe.header
        header_size = pe.sections[0].VirtualAddress_adj
        print(f"Mapping header {hex(image_base)}[{hex(header_size)}]")
        self.dp.write(image_base, header)
        self.dp.protect(image_base, header_size, PAGE_READONLY)

        for section in pe.sections:
            name = section.Name.rstrip(b"\0")
            rva = section.VirtualAddress_adj
            va = image_base + rva
            mask = section_alignment - 1
            size = (section.Misc_VirtualSize + mask) & ~mask
            flags = section.Characteristics
            data = section.get_data()
            assert flags & IMAGE_SCN_MEM_SHARED == 0
            assert flags & IMAGE_SCN_MEM_READ != 0
            execute = flags & IMAGE_SCN_MEM_EXECUTE
            write = flags & IMAGE_SCN_MEM_WRITE
            protect = PAGE_READONLY
            if write:
                protect = PAGE_READWRITE
            if execute:
                protect <<= 4
            print(f"Mapping section '{name.decode()}' {hex(rva)}[{hex(rva)}] -> {hex(va)}")
            self.dp.write(va, data)
            self.dp.protect(va, size, protect)

        # TODO: implement relocations
        reloc_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
        assert reloc_dir.VirtualAddress == 0 and reloc_dir.Size == 0
        # TODO: set image base in header

        return image_base, image_size, pe

    def load_dll(self, file_name: str, file_data: bytes):
        self.dp.handles.map_file("\\??\\" + file_name, FileObject(file_name, file_data))
        argument_ptr = self.dp.allocate(0x1000)
        utf16 = file_name.encode("utf-16-le")
        if self.dp._x64:
            argument_data = struct.pack("<IIQHHIQ", 0, 0, 0, len(utf16), len(utf16) + 2, 0, argument_ptr + 32)
            argument_data += utf16
            argument_data += b"\0"
            search_path = argument_ptr + len(argument_data)
            argument_data += b"Z:\\"
            image_type = argument_ptr
            image_base_address = image_type + 8
            image_file_name = image_base_address + 8
        else:
            assert False  # TODO
        self.dp.write(argument_ptr, argument_data)

        print(f"LdrLoadDll({file_name})")
        status = self.dp.call(self.dp.LdrLoadDll, [1, image_type, image_file_name, image_base_address])
        print(f"status = {hex(status)}")
        return self.dp.read_ptr(image_base_address)
