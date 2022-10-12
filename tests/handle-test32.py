from dumpulator import Dumpulator
from dumpulator.native import *

def main():
    dp = Dumpulator("TestHarness_x86.dmp")

    dp.handles.create_file("test_file.txt", FILE_OPEN)
    dp.handles.create_file("nonexistant_file.txt", FILE_CREATE)

    with open("TestHarness/bin/HandleTest_x86.dll", "rb") as dll:
        dll_data = dll.read()

        dp.map_module(dll_data, "HandleTest_x86.dll")

        for export in dp.modules["HandleTest_x86.dll"].exports:
            print(f"\n---- calling {export.name} ----\n")
            dp.call(export.address)


if __name__ == '__main__':
    main()
