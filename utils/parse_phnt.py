# pip install libclang
import json
import sys
from typing import *

import clang.cindex
from clang.cindex import *
from collections import OrderedDict

# Resources:
# https://gregoryszorc.com/blog/2012/05/14/python-bindings-updates-in-clang-3.1/
# https://sudonull.com/post/907-An-example-of-parsing-C-code-using-libclang-in-Python
# https://github.com/StatisKit/AutoWIG
# https://github.com/tekord/Python-Clang-RTTI-Generator-Example

def filter_by_folder(
        nodes: Iterable[Cursor],
        folder: str
) -> Iterable[Cursor]:
    for i in nodes:
        if folder in str(i.location.file):
            yield i

def filter_by_kind(
    nodes: Iterable[Cursor],
    kinds: list
) -> Iterable[Cursor]:
    for i in nodes:
        if i.kind in kinds:
            yield i

class EnumType:
    def __init__(self, name: str):
        self.name = name.lstrip('_')
        self.values: [(str, int)] = []

    def format_python(self):
        r = f"class {self.name}(Enum):\n"
        for name, value in self.values:
            r += f"    {name} = {value}\n"
        r += f"make_global({self.name})\n"
        return r

class FunctionArgument:
    def __init__(self, name: str):
        self.name = name
        self.typename = ""
        self.is_ptr = False
        self.sal = ""

class FunctionType:
    def __init__(self, name: str):
        self.name = name
        self.arguments: [FunctionArgument] = []

    def format_python(self):
        r = "@syscall\n"
        r += f"def {self.name}(dp: Dumpulator"
        indent = (len(self.name) + 5) * ' '
        a: FunctionArgument
        for i, a in enumerate(self.arguments):
            r += ",\n"
            pytype = f"P({a.typename})" if a.is_ptr else a.typename
            if len(a.sal) > 0:
                assert "\"" not in a.sal and "\\" not in a.sal
                r += f"{indent}{a.name}: Annotated[{pytype}, \"{a.sal}\"]"
            else:
                r += f"{indent}{a.name}: {pytype}"
        r += "\n"
        r += f"{indent}):\n"
        r += "    raise NotImplementedError()\n"

        return r

# This script was only tested on Windows, Visual Studio 2019
# phnt version: https://github.com/processhacker/phnt/commit/49539260245f4291b699884a9ef4552530c8cfa4
def main():
    if len(sys.argv) < 2:
        print("Usage: parse_phnt.py c:\\projects\\phnt")
        sys.exit(1)

    phnt_dir = sys.argv[1]
    index = Index.create()
    tu = index.parse("phnt.c", args=[f"-I{phnt_dir}"], options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
    diag: Diagnostic
    parse_errors = False
    for diag in tu.diagnostics:
        if diag.severity in [Diagnostic.Error, Diagnostic.Fatal]:
            print(diag)
            parse_errors = True
    if parse_errors:
        sys.exit(1)

    cursor: Cursor = tu.cursor
    phnt_nodes = list(filter_by_folder(cursor.get_children(), phnt_dir))
    e: Cursor
    system_enums = OrderedDict()

    # This is bad, these CursorKind.XXX are added in cindex.py, no autocomplete possible :(
    for e in filter_by_kind(cursor.get_children(), [CursorKind.ENUM_DECL]):
        if phnt_dir not in str(e.location.file):
            if e.spelling:
                et = EnumType(e.spelling)
                v: Cursor
                for v in e.get_children():
                    et.values.append((v.spelling, v.enum_value))
                if len(et.values) > 0:
                    system_enums[et.name] = et

    phnt_enums = OrderedDict()
    for e in filter_by_kind(phnt_nodes, [CursorKind.ENUM_DECL]):
        if e.spelling:
            et = EnumType(e.spelling)
            v: Cursor
            for v in e.get_children():
                et.values.append((v.spelling, v.enum_value))
            if len(et.values) > 0:
                phnt_enums[et.name] = et

    primitive_types = {
        "PVOID",
        "UCHAR",
        "CHAR",
        "USHORT",
        "ULONG",
        "LONG",
        "ULONG_PTR",
        "SIZE_T",
        "HANDLE",
        "ULONG64",
        "ULONGLONG",  # ULONG64
        "BYTE",  # UCHAR
        "RTL_ATOM",  # USHORT
        "NTSTATUS",  # ULONG
        "LANGID",  # USHORT
        "ALPC_HANDLE",  # HANDLE
        "NOTIFICATION_MASK",  # ULONG
        "SECURITY_INFORMATION",  # ULONG
        "EXECUTION_STATE",  # ULONG
        "SE_SIGNING_LEVEL",  # BYTE
        "ACCESS_MASK",  # ULONG
        "WNF_CHANGE_STAMP",  # ULONG
        "KAFFINITY",  # ULONG_PTR
        "BOOLEAN",  # bool
        "LOGICAL",  # ULONG
        "LCID",  # ULONG
        "LATENCY_TIME",  # Unnamed enum, hacked in by hand
        "PSID",  # PVOID
        "PWSTR",  # PVOID
    }

    file_data: Dict[str, List[str]] = {}
    f: Cursor
    functions = []
    for f in filter_by_kind(phnt_nodes, [CursorKind.FUNCTION_DECL]):
        if f.spelling.startswith("Zw"):
            loc: clang.cindex.SourceLocation = f.location
            file_name = loc.file.name
            if file_name not in file_data:
                with open(file_name, "r") as fp:
                    file_data[file_name] = [line.rstrip("\n") for line in fp.readlines()]
            file_lines = file_data[file_name]
            ft = FunctionType(f.spelling)
            a: Cursor
            for a in f.get_arguments():
                at = FunctionArgument(a.spelling)

                # Extract argument SAL annotation
                loc = a.location
                extent: clang.cindex.SourceRange = a.extent
                start: clang.cindex.SourceLocation = extent.start
                line = file_lines[loc.line - 1]
                at.sal = line[:start.column - 1].strip()

                # Extract argument type
                at.typename = str(a.type.spelling) \
                    .replace("volatile ", "") \
                    .replace("const ", "")

                if at.typename.startswith("P") and at.typename not in phnt_enums and at.typename not in primitive_types:
                    at.is_ptr = True
                    at.typename = at.typename[1:]

                # Hacky workarounds
                if at.typename == "LPGUID":
                    at.is_ptr = True
                    at.typename = "GUID"
                elif at.typename == "VOID *" or at.typename == "void *":
                    at.typename = "PVOID"
                elif at.typename.startswith("struct _") and at.typename.endswith(" *"):
                    assert not at.is_ptr
                    at.is_ptr = True
                    at.typename = at.typename[8:-2]
                elif at.typename.endswith(" *"):
                    assert not at.is_ptr
                    at.is_ptr = True
                    at.typename = at.typename[:-2]
                elif at.typename.endswith(" []"):
                    assert not at.is_ptr
                    at.is_ptr = True
                    at.typename = at.typename[:-3]
                elif at.typename.endswith("[]"):
                    assert not at.is_ptr
                    at.is_ptr = True
                    at.typename = at.typename[:-2]

                # Make sure the typename is a valid identifier
                if " " in at.typename:
                    ft.arguments.append(at)
                    print(ft.format_python())
                    assert False

                ft.arguments.append(at)
            functions.append(ft)

    unknown_types = set()
    struct_types = set()
    ft: FunctionType
    for ft in functions:
        at: FunctionArgument
        for at in ft.arguments:
            if not at.is_ptr and at.typename not in phnt_enums:
                if at.typename in system_enums:
                    print(f"Merge system enum {at.typename} into phnt_enums")
                    phnt_enums[at.typename] = system_enums[at.typename]
                elif at.typename not in primitive_types:
                    unknown_types.add(at.typename)
            elif at.is_ptr and at.typename not in primitive_types and at.typename not in phnt_enums:
                if at.typename in system_enums:
                    print(f"Merge system enum {at.typename} into phnt_enums")
                    phnt_enums[at.typename] = system_enums[at.typename]
                else:
                    struct_types.add(at.typename)

    # Anything printed here needs to be adjusted earlier on
    print(f"Found {len(unknown_types)} unknown primitive types:")
    for t in unknown_types:
        print("  " + t + ";")

    if len(sys.argv) > 2 and sys.argv[2] == "json":
        with open("ntsyscalls.json", "w") as f:
            data = {}
            for fn in functions:
                args = []
                arg: FunctionArgument
                for arg in fn.arguments:
                    args.append({
                        'name': arg.name,
                        'type': arg.typename + ("*" if arg.is_ptr else ""),
                        'sal': arg.sal
                    })
                data[fn.name] = args
            f.write(json.dumps(data, indent=2))
        with open("ntenums.json", "w") as f:
            data = {}
            e: EnumType
            for e in phnt_enums.values():
                values = []
                for name, value in e.values:
                    values.append({
                        'name': name,
                        'value': value
                    })
                data[e.name] = values
            f.write(json.dumps(data, indent=2))
    else:
        with open("ntsyscalls.py", "w") as f:
            for fn in functions:
                f.write(fn.format_python())
                f.write("\n")

        with open("ntenums.py", "w") as f:
            header = """
# Automatically generated with parse_phnt.py, do not edit
from enum import Enum
from .ntprimitives import make_global
            """
            f.write(header.strip() + "\n\n")

            for e in phnt_enums.values():
                f.write(e.format_python())
                f.write("\n")

        with open("ntstructs.py", "w") as f:
            header = """
# Automatically generated with parse_phnt.py, do not edit
            """
            f.write(header.strip() + "\n\n")

            for t in sorted(struct_types):
                if t == "CONTEXT":
                    continue
                f.write(f"class {t}:\n")
                f.write("    pass\n")
                f.write("\n")

if __name__ == '__main__':
    main()
