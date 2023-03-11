import os.path
import re
import subprocess
import sys
import inspect
from typing import Dict, List, Type, Tuple
from pathlib import Path

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
        if issubclass(obj, TestEnvironment) and obj is not TestEnvironment:
            # Extract the first capital word from the class name
            match = re.match(r"^([A-Z][a-z]+)", name)
            assert match is not None
            prefix = match[1]
            environments[prefix] = obj
    return environments

def collect_tests(dll_data) -> Tuple[Dict[str, List[str]], int]:
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

def run_tests(dll_path: str, harness_dump: str) -> Dict[str, bool]:
    print(f"--- {dll_path} ---")
    with open(dll_path, "rb") as dll:
        dll_data = dll.read()
    environments = collect_environments()
    tests, base = collect_tests(dll_data)
    results: Dict[str, bool] = {}
    for prefix, exports in tests.items():
        print(f"\nRunning {prefix.lower()} tests:")
        environment = environments.get(prefix, TestEnvironment)
        for export in exports:
            dp = Dumpulator(harness_dump, trace=True)
            module = dp.map_module(dll_data, dll_path, base)
            environment().setup(dp)
            test = module.find_export(export)
            assert test is not None
            print(f"--- Executing {test.name} at {hex(test.address)} ---")
            success = dp.call(test.address)
            results[export] = success != 0
            print(f"{export} -> {success}")
    return results

def print_results(result_name, results):
    max_len = len(result_name)
    for name in results:
        max_len = max(max_len, len(name))
    def format_value(value):
        return f"{value}{' ' * (max_len - len(value))} |"
    print(f"+---------+-{'-' * max_len}-+")
    print(f"| Status  | {format_value(f'Test ({result_name})')}")
    print(f"|---------|-{'-' * max_len}-+")
    all_success = True
    for name, success in results.items():
        print(f"| {'SUCCESS' if success else 'FAILURE'} | {format_value(name)}")
        if not success:
            all_success = False
    print(f"+---------+-{'-' * max_len}-+")
    return all_success

def vswhere(args):
    vswhere_path = os.path.expandvars(R"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe")
    if not os.path.exists(vswhere_path):
        return False
    command = f"\"{vswhere_path}\" -nologo -nocolor {args}"
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    result = stdout.decode("utf-8").strip().replace("\r", "")
    if process.returncode != 0:
        raise Exception(f"Command failed: {command}\n{result}")
    return stdout.decode("utf-8").strip()

def build_tests():
    if os.name != "nt":
        raise NotImplementedError(f"Unsupported OS: {os.name}")
    # Reference: https://stackoverflow.com/a/53319707/1806760
    msbuild_path = Path(vswhere(R"-latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe"))
    if not msbuild_path.exists():
        raise FileNotFoundError(f"Not found: {msbuild_path}")
    # Reference: https://github.com/microsoft/vswhere/wiki/Find-VC#batch
    vc_install_path = Path(vswhere(R"-latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath"))
    aux_path = vc_install_path.joinpath(R"VC\Auxiliary\Build")
    if not aux_path.exists():
        raise FileNotFoundError(f"Not found: {aux_path}")
    props = list(aux_path.glob("Microsoft.VCToolsVersion.v*.default.props"))
    latest_toolset = 0
    for prop in props:
        s = str(prop)
        # Extract the first capital word from the class name
        match = re.match(r"Microsoft\.VCToolsVersion\.v(\d+)\.default\.props", str(prop.name))
        assert match is not None, "No match found"
        latest_toolset = max(latest_toolset, int(match[1]))
    print(f"Latest platform toolset: v{latest_toolset}")

    def build(platform):
        command = f"\"{msbuild_path}\" /p:Platform={platform} /p:Configuration=Release /t:Rebuild /p:PlatformToolset=v{latest_toolset} DumpulatorTests\\DumpulatorTests.sln"
        print(f"Executing: {command}")
        process = subprocess.Popen(command)
        process.communicate()
        if process.returncode != 0:
            raise Exception(f"MSBuild failed (platform: {platform})")

    build("Win32")
    build("x64")

def main():
    dll_x64 = "DumpulatorTests/bin/Tests_x64.dll"
    dll_x86 = "DumpulatorTests/bin/Tests_x86.dll"
    if not os.path.exists(dll_x64) or not os.path.exists(dll_x86):
        print(f"Missing required files: {', '.join([dll_x64, dll_x86])}")
        try:
            build_tests()
            assert os.path.exists(dll_x64), f"Not found: {dll_x64}"
            assert os.path.exists(dll_x86), f"Not found: {dll_x86}"
        except Exception as x:
            print(x)
            print()
            print(f"You need to compile DumpulatorTests\\DumpulatorTests.sln using Visual Studio yourself")
            sys.exit(1)

    dmp_x64 = "HarnessMinimal_x64.dmp"
    dmp_x86 = "HarnessMinimal_x86.dmp"
    if not os.path.exists(dmp_x64) or not os.path.exists(dmp_x86):
        from download_artifacts import main as download_main
        if not download_main(dmp_x64, dmp_x86):
            sys.exit(1)

    results_x64 = run_tests(dll_x64, dmp_x64)
    print("")
    results_x86 = run_tests(dll_x86, dmp_x86)

    print("")
    success_x64 = print_results("x64", results_x64)
    print("")
    success_x86 = print_results("x86", results_x86)
    if not success_x64 or not success_x86:
        sys.exit(1)

if __name__ == "__main__":
    main()
