from dataclasses import dataclass, field
from typing import Dict, Optional, Union, List, Tuple

import pefile
from .memory import MemoryManager

# TODO: support forwarding to API sets
@dataclass
class ModuleExport:
    address: int
    ordinal: int
    name: str
    forward: Optional[Tuple[str, str]] = None

@dataclass
class Module:
    pe: pefile.PE
    path: str  # TODO(printup): use pathlib.Path
    name: str = field(init=False)
    exports: List[ModuleExport] = field(default_factory=list)
    _exports_by_address: Dict[int, int] = field(default_factory=dict)
    _exports_by_ordinal: Dict[int, int] = field(default_factory=dict)
    _exports_by_name: Dict[str, int] = field(default_factory=dict)
    base: int = field(init=False)
    size: int = field(init=False)
    entry: int = field(init=False)

    def __post_init__(self):
        self.path = self.path.replace("/", "\\")
        self.name = self.path.split("\\")[-1]
        self._parse_pe()

    def _parse_pe(self):
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.size = self.pe.OPTIONAL_HEADER.SizeOfImage
        self.entry = self.base + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        pe_exports = self.pe.DIRECTORY_ENTRY_EXPORT.symbols if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT") else []

        for pe_export in pe_exports:
            if pe_export.name:
                name = pe_export.name.decode("ascii")
            else:
                name = None

            if pe_export.forwarder is not None:
                va = 0
                forward = pe_export.forwarder.decode().split(".")
                forward = (f"{forward[0].lower()}.dll", str(forward[1]))
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
            return self.exports[index]
        elif isinstance(key, str):
            index = self._exports_by_name.get(key)
            if index is None:
                return None
            return self.exports[index]
        raise TypeError()

    def __repr__(self):
        return f"Module({hex(self.base)}, {hex(self.size)}, {repr(self.path)})"

    def __hash__(self):
        return hash((self.base, self.size, self.path))

    def __contains__(self, addr: int):
        return self.base <= addr < self.base + self.size

@dataclass
class ModuleManager:
    _memory: MemoryManager
    _name_lookup: Dict[str, int] = field(default_factory=dict)
    _modules: Dict[int, Module] = field(default_factory=dict)
    main: int = 0

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
            if region is not None and isinstance(region.info, Module):
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

    def resolve_export(self, module_key: Union[str, int], function_key: Union[str, int]):
        module = self.find(module_key)
        assert module is not None, f"Could not find module: {module_key}"
        export = module.find_export(function_key)
        assert export is not None, f"Could not find function: {module_key}:{function_key}"
        if export.forward is not None:
            return self.resolve_export(export.forward[0], export.forward[1])
        return export

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
