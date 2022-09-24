from dumpulator import Dumpulator
from dumpulator.native import *

test_funcs = {
    "console_output_test": 0x140001150,
    "read_file_test": 0x140001170,
    "write_file_test": 0x140001240,
    "write_file_offset_test": 0x140001330,
    "create_file_test": 0x140001420,
}


def main():
    dp = Dumpulator("HandleTest_x64.dmp")

    dp.handles.create_file("test_file.txt", FILE_OPEN)
    dp.handles.create_file("nonexistant_file.txt", FILE_CREATE)

    for name, addr in test_funcs.items():
        print(f"\n---- calling {name} ----\n")
        dp.call(addr)


if __name__ == '__main__':
    main()
