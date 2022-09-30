from .dumpulator import Dumpulator
from minidump.streams.ModuleListStream import MinidumpModule
from pefile import *
from unicorn import *
from .handles import *
from typing import List


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
    def __init__(self, dp: Dumpulator, name: str, rva: int, address: int):
        self.name = name
        self.rva = rva
        self.address = address
        self.dp = dp

    def __lt__(self, export: 'Function'):
        return self.address < export.address

    def __gt__(self, export: 'Function'):
        return self.address < export.address

    def __eq__(self, export: 'Function'):
        return self.address == export.address

    def __call__(self, args: List[int] = [], regs: dict = {}, count=0):
        return self.dp.call(self.address, args=args, regs=regs, count=count)


class NewModule:
    def __init__(self, dp: Dumpulator, file_data: bytes, file_name: str = "", requested_base: int = 0):
        self.dp = dp
        self.image_base = 0
        self.image_size = 0
        self.entry_point = 0
        self.full_path = file_name
        self.name = self.full_path.split('\\')[-1].lower()
        self._map_module(file_data, requested_base)

    def _map_module(self, file_data: bytes, requested_base: int = 0):
        print(f"Mapping module {self.name if self.name else '<unnamed>'}")
        pe = PE(name=None, data=file_data)
        self.pe = pe
        self.image_size = pe.OPTIONAL_HEADER.SizeOfImage
        section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
        bits = 64 if pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS else 32
        assert section_alignment == 0x1000, f"invalid section alignment of 0x{section_alignment:x}"
        if requested_base == 0:
            self.image_base = self.dp.allocate(self.image_size, True)
        else:
            self.image_base = requested_base
            self.dp._uc.mem_map(self.image_base, self.image_size)

        # fix relocations, saves to pe.__data__ buffer
        pe.relocate_image(self.image_base)

        self.entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase

        self.dp.info(f"image_base:  {self.image_base:x}")
        self.dp.info(f"entry_point: {self.entry_point:x}")

        header = bytes(pe.header)
        header_size = pe.sections[0].VirtualAddress_adj  # 0x1000
        print(f"Mapping header {hex(self.image_base)}[{hex(header_size)}]")
        self.dp.write(self.image_base, header)
        self.dp.protect(self.image_base, header_size, PAGE_READONLY)

        # https://vtopan.wordpress.com/2019/04/12/patching-resolving-imports-in-a-pe-file-python-pefile/
        # manually resolve imports
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            ordinal_flag = 2 ** (bits - 1)
            for iid in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = iid.dll.decode("utf-8").lower()
                assert dll_name in self.dp.modules, f"{dll_name} is not loaded"
                self.dp.info(f"resolving imports for {dll_name}")
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
                        assert ordinal in self.dp.modules[dll_name], f"ordinal #{ordinal} not in module"
                        imp_va = self.dp.modules[dll_name][ordinal].address
                        self.dp.info(f"\t{ordinal:<32}:0x{imp_va:0>16x}")
                    else:
                        hint = pe.get_word_from_data(pe.get_data(hint_rva, 2), 0)
                        func_name = pe.get_string_at_rva(ilt[idx].AddressOfData + 2, MAX_IMPORT_NAME_LENGTH)
                        func_name = func_name.decode("utf-8")
                        assert func_name in self.dp.modules[dll_name], f"{func_name} is not in {dll_name}"
                        imp_va = self.dp.modules[dll_name][func_name].address
                        self.dp.info(f"\t{func_name:<32}:0x{imp_va:0>16x}")
                    file_offset = iat[idx].get_field_absolute_offset('AddressOfData')
                    if bits == 64:
                        pe.__data__[file_offset:file_offset + 8] = struct.pack('<Q', imp_va)
                    else:
                        pe.__data__[file_offset:file_offset + 4] = struct.pack('<L', imp_va)

        for section in pe.sections:
            name = section.Name.rstrip(b"\0")
            rva = section.VirtualAddress_adj
            va = self.image_base + rva
            mask = section_alignment - 1
            size = (section.Misc_VirtualSize + mask) & ~mask
            flags = section.Characteristics
            data = bytes(section.get_data())
            assert flags & IMAGE_SCN_MEM_SHARED == 0
            read = flags & IMAGE_SCN_MEM_READ
            write = flags & IMAGE_SCN_MEM_WRITE
            execute = flags & IMAGE_SCN_MEM_EXECUTE
            protect = PAGE_NOACCESS
            if read:
                protect <<= 1
                if write:
                    protect <<= 1
                if execute:
                    protect <<= 4
            print(f"Mapping section '{name.decode()}' {hex(rva)}[{hex(rva)}][{hex(protect)}] -> {hex(va)}")
            self.dp.write(va, data)
            self.dp.protect(va, size, protect)


class Module:
    def __init__(self, dp: Dumpulator, minidump: Optional[MinidumpModule] = None, module: Optional[NewModule] = None):
        self._dp = dp
        if minidump is not None and module is None:
            self.full_path = minidump.name
            self.name = self.full_path.split('\\')[-1].lower()
            self.base_address = minidump.baseaddress
            self.size = minidump.size
            self.end_address = minidump.endaddress
            self.version_info = minidump.versioninfo
            self.checksum = minidump.checksum
            self.time_stamp = minidump.timestamp
            self.pe = self.__parse_pe()
            self.entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            self._functions = {}
            self.__parse_exports()  # adds exports to _functions dict
        elif module is not None and minidump is None:
            self.full_path = module.full_path
            self.name = module.name
            self.base_address = module.image_base
            self.size = module.image_size
            self.end_address = self.base_address + self.size
            self.version_info = 0
            self.checksum = 0
            self.time_stamp = 0
            self.pe = module.pe
            self.end_address = module.entry_point
            self._functions = {}
            self.__parse_exports()
        else:
            raise Exception()

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
                self._functions[name] = Function(self._dp, name, export.address, self.base_address + export.address)

    def find_function_name_offset(self, address: int) -> str:
        offset: int = 0xFFFFFFFFFFFFFFFF
        curr_func: Optional[Function] = None
        for func in self._functions.values():
            if func.address == address:
                return f"{self.name}:{func.name}"
            elif 0 < address - func.address < offset:
                curr_func = func
                offset = address - curr_func.address
        if curr_func is not None:
            return f"{self.name}:{curr_func.name}+0x{offset:x}"

    def find_function_name(self, address: int) -> str:
        for func in self._functions.values():
            if func.address == address:
                return f"{self.name}:{func.name}"
        return ""


class ModuleManager:
    def __init__(self, dp: Dumpulator):
        self.dp = dp
        self.peb = Peb(dp)
        self._modules = {}

        for dump_module in dp._minidump.modules.modules:
            module = Module(dp, minidump=dump_module)
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

    def add_module(self, file_data: bytes, file_name: str = "", requested_base: int = 0) -> Module:
        module = Module(self.dp, module=NewModule(self.dp, file_data, file_name, requested_base))
        self._modules[module.name] = module
        self.dp.info(f"Parsed {module.name} 0x{module.base_address:x}[0x{module.size}]")
        for func in module:
            self.dp.info(f"{func.name}:0x{func.address:0>16x}")
        return module

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

    def load_library(self, file_name: str, file_data: bytes, flags: int = 0):
        assert "kernel32.dll" in self.dp.modules
        self.dp.handles.map_file(file_name, FileObject(file_name, file_data))
        argument_ptr = self.dp.allocate(0x1000)
        self.dp.write(argument_ptr, file_name.encode("utf-16-le"))
        module = self.dp.modules["kernel32.dll"]["LoadLibraryExW"]([argument_ptr, 0, flags])
        return module
