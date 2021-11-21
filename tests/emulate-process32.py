from dumpulator import Dumpulator

dp = Dumpulator("StringEncryptionFun_x86.dmp")
dp.start(dp.regs.eip, count=0)
