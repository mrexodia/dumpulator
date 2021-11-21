from dumpulator import Dumpulator

dp = Dumpulator("stringenc32_entry.dmp", trace=True)
dp.start(dp.regs.eip, count=0)
