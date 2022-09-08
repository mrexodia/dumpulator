from dumpulator import Dumpulator

dp = Dumpulator("handle_test.dmp")
dp.call(0x004010B0)

# 64bit fails
# error: Invalid instruction (UC_ERR_INSN_INVALID), cip = 7ff818f6ae40 (ntdll!memset)
# 00007FF818F6AE40 | C4E37D18C0 01 | vinsertf128 ymm0,ymm0,xmm0,1 |