import sys

from dumpulator import Dumpulator

def main():
    if len(sys.argv) < 2:
        print("Usage: execute-dump.py my.dmp")
        sys.exit(1)

    dp = Dumpulator(sys.argv[1], trace=len(sys.argv) > 2)
    dp.start(dp.regs.cip)
    exit_code = dp.exit_code if dp.exit_code is not None else 1
    sys.exit(exit_code)

if __name__ == '__main__':
    main()
