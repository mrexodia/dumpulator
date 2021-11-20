from dumpulator import Dumpulator

dp = Dumpulator("test.dmp", trace=True)
temp_addr = dp.allocate(256)
dp.call(0x140001000, [temp_addr, 0x140003000])
decrypted = dp.read_str(temp_addr)
print(f"decrypted: '{decrypted}'")
