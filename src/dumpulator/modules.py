from typing import Dict, Optional, Type, Union, List

import pefile
from .memory import MemoryManager

# TODO: support forwarding to API sets
class ModuleExport:
    def __init__(self, address: int, ordinal: int, name: str, forward: str = ""):
        self.address = address
        self.ordinal = ordinal
        self.name = name
        self.forward = forward

class Module:
    def __init__(self, pe: pefile.PE, path: str):
        self.pe = pe
        self.path = path
        self.name = path.split("\\")[-1]
        self._exports_by_address: Dict[int, int] = {}
        self._exports_by_ordinal: Dict[int, int] = {}
        self._exports_by_name: Dict[str, int] = {}
        self.exports: List[ModuleExport] = []
        self._parse_pe()

    def _parse_pe(self):
        self.base: int = self.pe.OPTIONAL_HEADER.ImageBase
        self.size: int = self.pe.OPTIONAL_HEADER.SizeOfImage
        self.entry: int = self.base + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        pe_exports = self.pe.DIRECTORY_ENTRY_EXPORT.symbols if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT") else []

        for pe_export in pe_exports:
            if pe_export.name:
                name = pe_export.name.decode("ascii")
            else:
                name = None

            section = self.pe.get_section_by_rva(pe_export.address)
            section_name = section.Name.rstrip(b"\0").decode()

            # if import points to rdata then export is a forwarder
            # RtlNtdllName in x64 is the only function that breaks this rule
            if section_name == ".rdata" and name != "RtlNtdllName":
                va = 0
                forward = self.pe.get_string_at_rva(pe_export.address).decode()
                export = ModuleExport(va, pe_export.ordinal, name, forward)
            else:
                va = self.base + pe_export.address
                export = ModuleExport(va, pe_export.ordinal, name)

            self._exports_by_address[export.address] = len(self.exports)
            self._exports_by_ordinal[export.ordinal] = len(self.exports)
            if name is not None:
                self._exports_by_name[name] = len(self.exports)
            self.exports.append(export)

    def find_export(self, key: Union[str, int]):
        if isinstance(key, int):
            index = self._exports_by_ordinal.get(key, None)
            if index is None:
                index = self._exports_by_address.get(key, None)
            if index is None:
                return None
            export = self.exports[index]
            assert export.address != 0, f"export forward {self.name}:{export.name} is not resolved"
            return export
        elif isinstance(key, str):
            index = self._exports_by_name.get(key)
            if index is None:
                return None
            export = self.exports[index]
            assert export.address != 0, f"export forward {self.name}:{export.name} is not resolved"
            return export
        raise TypeError()

    def __repr__(self):
        return f"Module({hex(self.base)}, {hex(self.size)}, {repr(self.path)})"

    def __contains__(self, addr: int):
        return addr >= self.base and addr < self.base + self.size

class ModuleManager:
    def __init__(self, memory: MemoryManager):
        self._memory = memory
        self._name_lookup: Dict[str, int] = {}
        self._modules: Dict[int, Module] = {}

    def add(self, pe: pefile.PE, path: str):
        module = Module(pe, path)
        self._modules[module.base] = module
        region = self._memory.find_region(module.base)
        assert region.start == module.base
        assert region is not None
        region.info = module
        self._name_lookup[module.name] = module.base
        self._name_lookup[module.name.lower()] = module.base
        self._name_lookup[module.path] = module.base
        return module

    def find(self, key: Union[str, int]) -> Optional[Module]:
        if isinstance(key, int):
            region = self._memory.find_region(key)
            if region.info:
                assert isinstance(region.info, Module)
                return region.info
            return None
        if isinstance(key, str):
            base = self._name_lookup.get(key, None)
            if base is None:
                base = self._name_lookup.get(key.lower(), None)
            if base is None:
                return None
            return self.find(base)
        raise TypeError()

    def parse_forwards(self):
        for module in self._modules.values():
            for export in module.exports:
                if export.address == 0:
                    forward = export.forward.split(".")
                    fwd_module = self.find(f"{forward[0].lower()}.dll")
                    if fwd_module is None:
                        continue
                    fwd_export = fwd_module.find_export(forward[1])
                    if fwd_export is None:
                        continue
                    export.address = fwd_export.address

    def __getitem__(self, key: Union[str, int]) -> Module:
        module = self.find(key)
        if module is None:
            raise KeyError()
        return module

    def __contains__(self, key: Union[str, int]):
        return self.find(key) is not None

    def __iter__(self):
        for base in self._modules:
            yield self._modules[base]
