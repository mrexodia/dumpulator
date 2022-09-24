from dumpulator import Dumpulator

test_funcs = {
    "console_output_test": 0x4010C0,
    "read_file_test": 0x4010E0,
    "write_file_test": 0x401190,
    "write_file_offset_test": 0x401270,
    "create_file_test": 0x401350,
}


def main():
    dp = Dumpulator("HandleTest_x86.dmp")

    for name, addr in test_funcs.items():
        print(f"\n---- calling {name} ----\n")
        dp.call(addr)


if __name__ == '__main__':
    main()
