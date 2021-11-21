from dumpulator import Dumpulator

dp = Dumpulator("StringEncryptionFun_x86.dmp")
x = dp.regs.csp
print(dp.regs.csp)
x -= 4
dp.regs.csp = x
print(dp.regs.csp)
temp_addr = dp.allocate(256)
print(f"temp_addr: {temp_addr:0x}")
dp.call(0x401000, [temp_addr, 0x413000])
decrypted = dp.read_str(temp_addr)
print(f"decrypted: '{decrypted}'")
