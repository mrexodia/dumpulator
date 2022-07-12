from dumpulator import Dumpulator, syscall
from dumpulator.native import *

# Dummy syscall implementations

@syscall
def ZwOpenKey(dp: Dumpulator,
              KeyHandle: P(HANDLE),
              DesiredAccess: ACCESS_MASK,
              ObjectAttributes: P(OBJECT_ATTRIBUTES)
              ):
    return STATUS_NOT_IMPLEMENTED

def main():
    dp = Dumpulator("ExceptionTest64.dmp", trace=True)
    dp.start(dp.regs.rip)

if __name__ == '__main__':
    main()
