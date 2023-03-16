# pip install libclang
import json
import sys
from typing import *
from enum import Enum

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

class EnumValue:
    def __init__(self, name: str, value: int):
        self.name = name
        self.value = value
        self.comment = ""

class EnumType:
    def __init__(self, name: str):
        self.name: str = name.lstrip("_")
        self.values: List[EnumValue] = []

    def format_python(self):
        r = f"class {self.name}(Enum):\n"
        for evalue in self.values:
            r += f"    {evalue.name} = {evalue.value}"
            if evalue.comment:
                r += f"  # {evalue.comment}"
            r += "\n"
        return r

class FunctionArgument:
    def __init__(self, name: str):
        self.name = name
        self.typename = ""
        self.is_ptr = False
        self.sal = ""
        self.comment = ""

class FunctionType:
    def __init__(self, name: str):
        self.name = name
        self.arguments: [FunctionArgument] = []

    def format_python(self, body: Optional[str] = None):
        r = "@syscall\n"
        r += f"def {self.name}(dp: Dumpulator"
        indent = (len(self.name) + 5) * " "
        a: FunctionArgument
        for i, a in enumerate(self.arguments):
            r += ",\n"
            pytype = f"P[{a.typename}]" if a.is_ptr else a.typename
            if len(a.sal) > 0:
                assert "\"" not in a.sal and "\\" not in a.sal
                sal = f"SAL(\"{a.sal}\""
                if a.comment:
                    assert "\"" not in a.comment and "\\" not in a.comment
                    sal += f", \"{a.comment}\""
                sal += ")"
                r += f"{indent}{a.name}: Annotated[{pytype}, {sal}]"
            else:
                r += f"{indent}{a.name}: {pytype}"
        r += "\n"
        r += f"{indent}):\n"
        if body is None:
            r += "    raise NotImplementedError()\n"
        else:
            r += body

        return r

class FunctionBodies:
    def __init__(self, impl_file: Optional[str] = None):
        self.functions: Dict[str, str] = {}

        if impl_file is None:
            return

        with open(impl_file, "r") as f:
            self.lines = [line.rstrip("\n") for line in f.readlines()]

        class State(Enum):
            Imports = 0
            Neutral = 1
            FnType = 2
            FnBody = 3

        self.imports = ""
        current_name = ""
        current_body: List[str] = []
        state = State.Imports
        for line in self.lines:
            if state == State.Imports:
                if line == "@syscall":
                    state = State.Neutral
                else:
                    self.imports += line
                    self.imports += "\n"
            elif state == State.Neutral:
                if line.startswith("def Zw"):
                    assert len(current_body) == 0
                    current_name = line[4:line.index("(")]
                    state = State.FnType
            elif state == State.FnType:
                if line.strip() == "):":
                    state = State.FnBody
            elif state == State.FnBody:
                assert not line.startswith("def Zw")
                if line.startswith("@syscall"):
                    self.add_function_body(current_name, current_body)
                    current_body = []
                    state = State.Neutral
                else:
                    current_body.append(line)

        if len(current_body) > 0:
            self.add_function_body(current_name, current_body)

    def add_function_body(self, name: str, body: List[str]):
        assert len(body) > 0
        if body[-1] == "":
            body.pop()

        # Skip unimplemented functions
        if body == ["    raise NotImplementedError()"]:
            return

        final_body = ""
        for line in body:
            final_body += line
            final_body += "\n"

        assert name not in self.functions
        self.functions[name] = final_body

    def get(self, name) -> Optional[str]:
        return self.functions.get(name, None)

class FileState:
    def __init__(self):
        self.files: Dict[str, List[str]] = {}

    def lines(self, file_name: str):
        if file_name not in self.files:
            with open(file_name, "r") as fp:
                self.files[file_name] = [line.rstrip("\n") for line in fp.readlines()]
        return self.files[file_name]

def extract_line_comment(file_state: FileState, cursor: Cursor):
    end: clang.cindex.SourceLocation = cursor.extent.end
    line = file_state.lines(cursor.location.file.name)[end.line - 1]
    if end.column - 1 < len(line):
        comment = line[end.column - 1:]
        if comment.startswith(","):
            comment = comment[1:]
        comment = comment.strip()
        if comment.startswith("//"):
            return comment[2:].strip()
    return ""

def add_enum(file_state: FileState, enums : Dict[str, EnumType], edecl: Cursor):
    if edecl.spelling:
        et = EnumType(edecl.spelling)
        v: Cursor
        for v in edecl.get_children():
            ev = EnumValue(v.spelling, v.enum_value)
            ev.comment = extract_line_comment(file_state, v)
            et.values.append(ev)
        if len(et.values) > 0:
            enums[et.name] = et

# This script was only tested on Windows, Visual Studio 2019
# phnt version: https://github.com/processhacker/phnt/commit/49539260245f4291b699884a9ef4552530c8cfa4
def main():
    if len(sys.argv) < 2:
        print("Usage: parse_phnt.py c:\\projects\\phnt")
        sys.exit(1)

    file_state = FileState()
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
    system_enums: Dict[str, EnumType] = OrderedDict()

    # This is bad, these CursorKind.XXX are added in cindex.py, no autocomplete possible :(
    edecl: Cursor
    for edecl in filter_by_kind(cursor.get_children(), [CursorKind.ENUM_DECL]):
        if phnt_dir not in str(edecl.location.file):
            add_enum(file_state, system_enums, edecl)

    phnt_enums: Dict[str, EnumType] = OrderedDict()
    for edecl in filter_by_kind(phnt_nodes, [CursorKind.ENUM_DECL]):
        if edecl.spelling:
            add_enum(file_state, phnt_enums, edecl)

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

    fdecl: Cursor
    functions: List[FunctionType] = []
    for fdecl in filter_by_kind(phnt_nodes, [CursorKind.FUNCTION_DECL]):
        if fdecl.spelling.startswith("Zw"):
            loc: clang.cindex.SourceLocation = fdecl.location
            file_lines = file_state.lines(loc.file.name)
            ft = FunctionType(fdecl.spelling)
            a: Cursor
            for a in fdecl.get_arguments():
                at = FunctionArgument(a.spelling)

                # Extract argument SAL annotation
                loc = a.location
                extent: clang.cindex.SourceRange = a.extent
                start: clang.cindex.SourceLocation = extent.start
                line = file_lines[loc.line - 1]
                at.sal = line[:start.column - 1].strip()
                at.comment = extract_line_comment(file_state, a)

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
                        "name": arg.name,
                        "type": arg.typename + ("*" if arg.is_ptr else ""),
                        "sal": arg.sal,
                        "comment": arg.comment
                    })
                data[fn.name] = args
            f.write(json.dumps(data, indent=2))
        with open("ntenums.json", "w") as f:
            data = {}
            e: EnumType
            for e in phnt_enums.values():
                values = []
                for evalue in e.values:
                    values.append({
                        "name": evalue.name,
                        "value": evalue.value,
                        "comment": evalue.comment
                    })
                data[e.name] = values
            f.write(json.dumps(data, indent=2))
    else:
        if len(sys.argv) > 2 and sys.argv[2].endswith(".py"):
            bodies = FunctionBodies(sys.argv[2])
        else:
            bodies = FunctionBodies()

        with open("ntsyscalls.py", "w") as f:
            f.write(bodies.imports)
            for fn in functions:
                f.write(fn.format_python(bodies.get(fn.name)))
                f.write("\n")

        with open("ntenums.py", "w") as f:
            header = """
# Automatically generated with parse_phnt.py, do not edit
from enum import Enum
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

if __name__ == "__main__":
    main()
