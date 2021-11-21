from dumpulator import Dumpulator

dp = Dumpulator("StringEncryptionFun_x64.dmp")
dp.start(dp.regs.rip)
