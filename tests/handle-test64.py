from dumpulator import Dumpulator

test_funcs = {
    "console_output_test": 0x140001150,
    "read_file_test": 0x140001170,
    "write_file_test": 0x140001240,
    "write_file_offset_test": 0x140001330,
}


# will fail with error: Invalid instruction (UC_ERR_INSN_INVALID), cip = 7ffc9648a980
# 00007FFC9648A980 | C4E37D18C0 01 | vinsertf128 ymm0,ymm0,xmm0,1 |
def main():
    dp = Dumpulator("HandleTest_x64.dmp")

    for name, addr in test_funcs.items():
        print(f"\n---- calling {name} ----\n")
        dp.call(addr)


if __name__ == '__main__':
    main()
