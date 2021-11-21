from dumpulator import Dumpulator

dp = Dumpulator("StringEncryptionFun_x86.dmp")
temp_addr = dp.allocate(256)
dp.call(0x401000, [temp_addr, 0x413000])
decrypted = dp.read_str(temp_addr)
print(f"decrypted: '{decrypted}'")
