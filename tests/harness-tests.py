import re
import sys
import inspect
from typing import Dict, List, Type

from dumpulator import Dumpulator
from dumpulator.native import *
from dumpulator.modules import Module
import pefile

class TestEnvironment:
    def setup(self, dp: Dumpulator):
        pass

class HandleEnvironment(TestEnvironment):
    def setup(self, dp: Dumpulator):
        dp.handles.create_file("test_file.txt", FILE_OPEN)
        dp.handles.create_file("nonexistent_file.txt", FILE_CREATE)

def collect_environments():
    environments: Dict[str, Type[TestEnvironment]] = {}
    for name, obj in inspect.getmembers(sys.modules[__name__], inspect.isclass):
        if issubclass(obj, TestEnvironment) and not obj is TestEnvironment:
            # Extract the first capital word from the class name
            match = re.match(r"^([A-Z][a-z]+)", name)
            assert match is not None
            prefix = match.group(1)
            environments[prefix] = obj
    return environments

def collect_tests(dll_data):
    pe = pefile.PE(data=dll_data, fast_load=True)
    module = Module(pe, "tests.dll")
    tests: Dict[str, List[str]] = {}
    for export in module.exports:
        assert "_" in export.name, f"Invalid test export '{export.name}'"
        prefix = export.name.split("_")[0]
        if prefix not in tests:
            tests[prefix] = []
        tests[prefix].append(export.name)
    return tests, module.base

def run_tests(dll_path: str, harness_dump: str):
    print(f"--- {dll_path} ---")
    with open(dll_path, "rb") as dll:
        dll_data = dll.read()
    environments = collect_environments()
    tests, base = collect_tests(dll_data)
    for prefix, exports in tests.items():
        print(f"\nRunning {prefix.lower()} tests:")
        environment = environments.get(prefix, TestEnvironment)
        for export in exports:
            dp = Dumpulator(harness_dump, trace=True)
            module = dp.map_module(dll_data, dll_path, base)
            # Register the EXCEPTION_DIRECTORY
            if dp.ptr_size() == 8:
                dir = module.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]]
                va = module.base + dir.VirtualAddress
                size = dir.Size
                assert size % 12 == 0
                RtlAddFunctionTable = dp.modules.resolve_export("ntdll.dll", "RtlAddFunctionTable").address
                success = dp.call(RtlAddFunctionTable, [va, size // 12, module.base])
                print(f"RtlAddFunctionTable: {success}")
            environment().setup(dp)
            test = module.find_export(export)
            assert test is not None
            print(f"--- Executing {test.name} at {hex(test.address)} ---")
            success = dp.call(test.address)
            print(f"{export} -> {success}")

def main():
    run_tests("DumpulatorTests/bin/Tests_x64.dll", "HarnessMinimal_x64.dmp")
    print("")
    run_tests("DumpulatorTests/bin/Tests_x86.dll", "HarnessMinimal_x86.dmp")

if __name__ == "__main__":
    main()
