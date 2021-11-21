from dumpulator import Dumpulator

dp = Dumpulator("StringEncryptionFun_x64.dmp")
temp_addr = dp.allocate(256)
dp.call(0x140001000, [temp_addr, 0x140017000])
decrypted = dp.read_str(temp_addr)
print(f"decrypted: '{decrypted}'")
