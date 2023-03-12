from dumpulator import Dumpulator, syscall
from dumpulator.native import *

# Dummy syscall implementations

@syscall
def ZwOpenKey(dp: Dumpulator,
              KeyHandle: P[HANDLE],
              DesiredAccess: ACCESS_MASK,
              ObjectAttributes: P[OBJECT_ATTRIBUTES]
              ):
    return STATUS_NOT_IMPLEMENTED

@syscall
def ZwQueryVirtualMemory(dp: Dumpulator,
                         ProcessHandle: HANDLE,
                         BaseAddress: PVOID,
                         MemoryInformationClass: MEMORY_INFORMATION_CLASS,
                         MemoryInformation: PVOID,
                         MemoryInformationLength: SIZE_T,
                         ReturnLength: P[SIZE_T]
                         ):
    return STATUS_SUCCESS

@syscall
def ZwOpenSection(dp: Dumpulator,
                  SectionHandle: P[HANDLE],
                  DesiredAccess: ACCESS_MASK,
                  ObjectAttributes: P[OBJECT_ATTRIBUTES]
                  ):
    return STATUS_NOT_IMPLEMENTED

@syscall
def ZwSetEvent(dp: Dumpulator,
               EventHandle: HANDLE,
               PreviousState: P[LONG]
               ):
    return STATUS_NOT_IMPLEMENTED

def main():
    dp = Dumpulator("StringEncryptionFun_x64.dmp")
    dp.start(dp.regs.rip)

if __name__ == '__main__':
    main()
