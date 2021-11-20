from dumpulator import Dumpulator

dp = Dumpulator("test.dmp", trace=False)
dp.start(dp.regs.rip)
