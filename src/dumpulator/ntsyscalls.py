import ctypes
import struct
import unicorn

from .dumpulator import Dumpulator
from .native import *
from .handles import *
from .memory import *
from pathlib import Path

def syscall(func):
    name: str = func.__name__
    if name[:2] not in ["Zw", "Nt"]:
        raise Exception(f"All syscalls have to be prefixed with 'Zw' or 'Nt'")
    # Add the function with both prefixes to avoid name bugs
    from .dumpulator import syscall_functions
    syscall_functions["Zw" + name[2:]] = func
    syscall_functions["Nt" + name[2:]] = func
    return func

@syscall
def ZwAcceptConnectPort(dp: Dumpulator,
                        PortHandle: Annotated[P[HANDLE], SAL("_Out_")],
                        PortContext: Annotated[PVOID, SAL("_In_opt_")],
                        ConnectionRequest: Annotated[P[PORT_MESSAGE], SAL("_In_")],
                        AcceptConnection: Annotated[BOOLEAN, SAL("_In_")],
                        ServerView: Annotated[P[PORT_VIEW], SAL("_Inout_opt_")],
                        ClientView: Annotated[P[REMOTE_PORT_VIEW], SAL("_Out_opt_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwAccessCheck(dp: Dumpulator,
                  SecurityDescriptor: Annotated[P[SECURITY_DESCRIPTOR], SAL("_In_")],
                  ClientToken: Annotated[HANDLE, SAL("_In_")],
                  DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                  GenericMapping: Annotated[P[GENERIC_MAPPING], SAL("_In_")],
                  PrivilegeSet: Annotated[P[PRIVILEGE_SET], SAL("_Out_writes_bytes_(*PrivilegeSetLength)")],
                  PrivilegeSetLength: Annotated[P[ULONG], SAL("_Inout_")],
                  GrantedAccess: Annotated[P[ACCESS_MASK], SAL("_Out_")],
                  AccessStatus: Annotated[P[NTSTATUS], SAL("_Out_")]
                  ):
    raise NotImplementedError()

@syscall
def ZwAccessCheckAndAuditAlarm(dp: Dumpulator,
                               SubsystemName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                               HandleId: Annotated[PVOID, SAL("_In_opt_")],
                               ObjectTypeName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                               ObjectName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                               SecurityDescriptor: Annotated[P[SECURITY_DESCRIPTOR], SAL("_In_")],
                               DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                               GenericMapping: Annotated[P[GENERIC_MAPPING], SAL("_In_")],
                               ObjectCreation: Annotated[BOOLEAN, SAL("_In_")],
                               GrantedAccess: Annotated[P[ACCESS_MASK], SAL("_Out_")],
                               AccessStatus: Annotated[P[NTSTATUS], SAL("_Out_")],
                               GenerateOnClose: Annotated[P[BOOLEAN], SAL("_Out_")]
                               ):
    raise NotImplementedError()

@syscall
def ZwAccessCheckByType(dp: Dumpulator,
                        SecurityDescriptor: Annotated[P[SECURITY_DESCRIPTOR], SAL("_In_")],
                        PrincipalSelfSid: Annotated[PSID, SAL("_In_opt_")],
                        ClientToken: Annotated[HANDLE, SAL("_In_")],
                        DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                        ObjectTypeList: Annotated[P[OBJECT_TYPE_LIST], SAL("_In_reads_(ObjectTypeListLength)")],
                        ObjectTypeListLength: Annotated[ULONG, SAL("_In_")],
                        GenericMapping: Annotated[P[GENERIC_MAPPING], SAL("_In_")],
                        PrivilegeSet: Annotated[P[PRIVILEGE_SET], SAL("_Out_writes_bytes_(*PrivilegeSetLength)")],
                        PrivilegeSetLength: Annotated[P[ULONG], SAL("_Inout_")],
                        GrantedAccess: Annotated[P[ACCESS_MASK], SAL("_Out_")],
                        AccessStatus: Annotated[P[NTSTATUS], SAL("_Out_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwAccessCheckByTypeAndAuditAlarm(dp: Dumpulator,
                                     SubsystemName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                                     HandleId: Annotated[PVOID, SAL("_In_opt_")],
                                     ObjectTypeName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                                     ObjectName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                                     SecurityDescriptor: Annotated[P[SECURITY_DESCRIPTOR], SAL("_In_")],
                                     PrincipalSelfSid: Annotated[PSID, SAL("_In_opt_")],
                                     DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                                     AuditType: Annotated[AUDIT_EVENT_TYPE, SAL("_In_")],
                                     Flags: Annotated[ULONG, SAL("_In_")],
                                     ObjectTypeList: Annotated[P[OBJECT_TYPE_LIST], SAL("_In_reads_opt_(ObjectTypeListLength)")],
                                     ObjectTypeListLength: Annotated[ULONG, SAL("_In_")],
                                     GenericMapping: Annotated[P[GENERIC_MAPPING], SAL("_In_")],
                                     ObjectCreation: Annotated[BOOLEAN, SAL("_In_")],
                                     GrantedAccess: Annotated[P[ACCESS_MASK], SAL("_Out_")],
                                     AccessStatus: Annotated[P[NTSTATUS], SAL("_Out_")],
                                     GenerateOnClose: Annotated[P[BOOLEAN], SAL("_Out_")]
                                     ):
    raise NotImplementedError()

@syscall
def ZwAccessCheckByTypeResultList(dp: Dumpulator,
                                  SecurityDescriptor: Annotated[P[SECURITY_DESCRIPTOR], SAL("_In_")],
                                  PrincipalSelfSid: Annotated[PSID, SAL("_In_opt_")],
                                  ClientToken: Annotated[HANDLE, SAL("_In_")],
                                  DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                                  ObjectTypeList: Annotated[P[OBJECT_TYPE_LIST], SAL("_In_reads_(ObjectTypeListLength)")],
                                  ObjectTypeListLength: Annotated[ULONG, SAL("_In_")],
                                  GenericMapping: Annotated[P[GENERIC_MAPPING], SAL("_In_")],
                                  PrivilegeSet: Annotated[P[PRIVILEGE_SET], SAL("_Out_writes_bytes_(*PrivilegeSetLength)")],
                                  PrivilegeSetLength: Annotated[P[ULONG], SAL("_Inout_")],
                                  GrantedAccess: Annotated[P[ACCESS_MASK], SAL("_Out_writes_(ObjectTypeListLength)")],
                                  AccessStatus: Annotated[P[NTSTATUS], SAL("_Out_writes_(ObjectTypeListLength)")]
                                  ):
    raise NotImplementedError()

@syscall
def ZwAccessCheckByTypeResultListAndAuditAlarm(dp: Dumpulator,
                                               SubsystemName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                                               HandleId: Annotated[PVOID, SAL("_In_opt_")],
                                               ObjectTypeName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                                               ObjectName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                                               SecurityDescriptor: Annotated[P[SECURITY_DESCRIPTOR], SAL("_In_")],
                                               PrincipalSelfSid: Annotated[PSID, SAL("_In_opt_")],
                                               DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                                               AuditType: Annotated[AUDIT_EVENT_TYPE, SAL("_In_")],
                                               Flags: Annotated[ULONG, SAL("_In_")],
                                               ObjectTypeList: Annotated[P[OBJECT_TYPE_LIST], SAL("_In_reads_opt_(ObjectTypeListLength)")],
                                               ObjectTypeListLength: Annotated[ULONG, SAL("_In_")],
                                               GenericMapping: Annotated[P[GENERIC_MAPPING], SAL("_In_")],
                                               ObjectCreation: Annotated[BOOLEAN, SAL("_In_")],
                                               GrantedAccess: Annotated[P[ACCESS_MASK], SAL("_Out_writes_(ObjectTypeListLength)")],
                                               AccessStatus: Annotated[P[NTSTATUS], SAL("_Out_writes_(ObjectTypeListLength)")],
                                               GenerateOnClose: Annotated[P[BOOLEAN], SAL("_Out_")]
                                               ):
    raise NotImplementedError()

@syscall
def ZwAccessCheckByTypeResultListAndAuditAlarmByHandle(dp: Dumpulator,
                                                       SubsystemName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                                                       HandleId: Annotated[PVOID, SAL("_In_opt_")],
                                                       ClientToken: Annotated[HANDLE, SAL("_In_")],
                                                       ObjectTypeName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                                                       ObjectName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                                                       SecurityDescriptor: Annotated[P[SECURITY_DESCRIPTOR], SAL("_In_")],
                                                       PrincipalSelfSid: Annotated[PSID, SAL("_In_opt_")],
                                                       DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                                                       AuditType: Annotated[AUDIT_EVENT_TYPE, SAL("_In_")],
                                                       Flags: Annotated[ULONG, SAL("_In_")],
                                                       ObjectTypeList: Annotated[P[OBJECT_TYPE_LIST], SAL("_In_reads_opt_(ObjectTypeListLength)")],
                                                       ObjectTypeListLength: Annotated[ULONG, SAL("_In_")],
                                                       GenericMapping: Annotated[P[GENERIC_MAPPING], SAL("_In_")],
                                                       ObjectCreation: Annotated[BOOLEAN, SAL("_In_")],
                                                       GrantedAccess: Annotated[P[ACCESS_MASK], SAL("_Out_writes_(ObjectTypeListLength)")],
                                                       AccessStatus: Annotated[P[NTSTATUS], SAL("_Out_writes_(ObjectTypeListLength)")],
                                                       GenerateOnClose: Annotated[P[BOOLEAN], SAL("_Out_")]
                                                       ):
    raise NotImplementedError()

@syscall
def ZwAcquireCMFViewOwnership(dp: Dumpulator,
                              TimeStamp: Annotated[P[ULONGLONG], SAL("_Out_")],
                              tokenTaken: Annotated[P[BOOLEAN], SAL("_Out_")],
                              replaceExisting: Annotated[BOOLEAN, SAL("_In_")]
                              ):
    raise NotImplementedError()

@syscall
def ZwAddAtom(dp: Dumpulator,
              AtomName: Annotated[PWSTR, SAL("_In_reads_bytes_opt_(Length)")],
              Length: Annotated[ULONG, SAL("_In_")],
              Atom: Annotated[P[RTL_ATOM], SAL("_Out_opt_")]
              ):
    raise NotImplementedError()

@syscall
def ZwAddAtomEx(dp: Dumpulator,
                AtomName: Annotated[PWSTR, SAL("_In_reads_bytes_opt_(Length)")],
                Length: Annotated[ULONG, SAL("_In_")],
                Atom: Annotated[P[RTL_ATOM], SAL("_Out_opt_")],
                Flags: Annotated[ULONG, SAL("_In_")]
                ):
    raise NotImplementedError()

@syscall
def ZwAddBootEntry(dp: Dumpulator,
                   BootEntry: Annotated[P[BOOT_ENTRY], SAL("_In_")],
                   Id: Annotated[P[ULONG], SAL("_Out_opt_")]
                   ):
    raise NotImplementedError()

@syscall
def ZwAddDriverEntry(dp: Dumpulator,
                     DriverEntry: Annotated[P[EFI_DRIVER_ENTRY], SAL("_In_")],
                     Id: Annotated[P[ULONG], SAL("_Out_opt_")]
                     ):
    raise NotImplementedError()

@syscall
def ZwAdjustGroupsToken(dp: Dumpulator,
                        TokenHandle: Annotated[HANDLE, SAL("_In_")],
                        ResetToDefault: Annotated[BOOLEAN, SAL("_In_")],
                        NewState: Annotated[P[TOKEN_GROUPS], SAL("_In_opt_")],
                        BufferLength: Annotated[ULONG, SAL("_In_opt_")],
                        PreviousState: Annotated[P[TOKEN_GROUPS], SAL("_Out_writes_bytes_to_opt_(BufferLength, *ReturnLength)")],
                        ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwAdjustPrivilegesToken(dp: Dumpulator,
                            TokenHandle: Annotated[HANDLE, SAL("_In_")],
                            DisableAllPrivileges: Annotated[BOOLEAN, SAL("_In_")],
                            NewState: Annotated[P[TOKEN_PRIVILEGES], SAL("_In_opt_")],
                            BufferLength: Annotated[ULONG, SAL("_In_")],
                            PreviousState: Annotated[P[TOKEN_PRIVILEGES], SAL("_Out_writes_bytes_to_opt_(BufferLength, *ReturnLength)")],
                            ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                            ):
    raise NotImplementedError()

@syscall
def ZwAdjustTokenClaimsAndDeviceGroups(dp: Dumpulator,
                                       TokenHandle: Annotated[HANDLE, SAL("_In_")],
                                       UserResetToDefault: Annotated[BOOLEAN, SAL("_In_")],
                                       DeviceResetToDefault: Annotated[BOOLEAN, SAL("_In_")],
                                       DeviceGroupsResetToDefault: Annotated[BOOLEAN, SAL("_In_")],
                                       NewUserState: Annotated[P[TOKEN_SECURITY_ATTRIBUTES_INFORMATION], SAL("_In_opt_")],
                                       NewDeviceState: Annotated[P[TOKEN_SECURITY_ATTRIBUTES_INFORMATION], SAL("_In_opt_")],
                                       NewDeviceGroupsState: Annotated[P[TOKEN_GROUPS], SAL("_In_opt_")],
                                       UserBufferLength: Annotated[ULONG, SAL("_In_")],
                                       PreviousUserState: Annotated[P[TOKEN_SECURITY_ATTRIBUTES_INFORMATION], SAL("_Out_writes_bytes_to_opt_(UserBufferLength, *UserReturnLength)")],
                                       DeviceBufferLength: Annotated[ULONG, SAL("_In_")],
                                       PreviousDeviceState: Annotated[P[TOKEN_SECURITY_ATTRIBUTES_INFORMATION], SAL("_Out_writes_bytes_to_opt_(DeviceBufferLength, *DeviceReturnLength)")],
                                       DeviceGroupsBufferLength: Annotated[ULONG, SAL("_In_")],
                                       PreviousDeviceGroups: Annotated[P[TOKEN_GROUPS], SAL("_Out_writes_bytes_to_opt_(DeviceGroupsBufferLength, *DeviceGroupsReturnBufferLength)")],
                                       UserReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")],
                                       DeviceReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")],
                                       DeviceGroupsReturnBufferLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                                       ):
    raise NotImplementedError()

@syscall
def ZwAlertResumeThread(dp: Dumpulator,
                        ThreadHandle: Annotated[HANDLE, SAL("_In_")],
                        PreviousSuspendCount: Annotated[P[ULONG], SAL("_Out_opt_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwAlertThread(dp: Dumpulator,
                  ThreadHandle: Annotated[HANDLE, SAL("_In_")]
                  ):
    raise NotImplementedError()

@syscall
def ZwAlertThreadByThreadId(dp: Dumpulator,
                            ThreadId: Annotated[HANDLE, SAL("_In_")]
                            ):
    raise NotImplementedError()

@syscall
def ZwAllocateLocallyUniqueId(dp: Dumpulator,
                              Luid: Annotated[P[LUID], SAL("_Out_")]
                              ):
    raise NotImplementedError()

@syscall
def ZwAllocateReserveObject(dp: Dumpulator,
                            MemoryReserveHandle: Annotated[P[HANDLE], SAL("_Out_")],
                            ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
                            Type: Annotated[MEMORY_RESERVE_TYPE, SAL("_In_")]
                            ):
    raise NotImplementedError()

@syscall
def ZwAllocateUserPhysicalPages(dp: Dumpulator,
                                ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                                NumberOfPages: Annotated[P[ULONG_PTR], SAL("_Inout_")],
                                UserPfnArray: Annotated[P[ULONG_PTR], SAL("_Out_writes_(*NumberOfPages)")]
                                ):
    raise NotImplementedError()

@syscall
def ZwAllocateUserPhysicalPagesEx(dp: Dumpulator,
                                  ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                                  NumberOfPages: Annotated[P[ULONG_PTR], SAL("_Inout_")],
                                  UserPfnArray: Annotated[P[ULONG_PTR], SAL("_Out_writes_(*NumberOfPages)")],
                                  ExtendedParameters: Annotated[P[MEM_EXTENDED_PARAMETER], SAL("_Inout_updates_opt_(ParameterCount)")],
                                  ExtendedParameterCount: Annotated[ULONG, SAL("_In_")]
                                  ):
    raise NotImplementedError()

@syscall
def ZwAllocateUuids(dp: Dumpulator,
                    Time: Annotated[P[ULARGE_INTEGER], SAL("_Out_")],
                    Range: Annotated[P[ULONG], SAL("_Out_")],
                    Sequence: Annotated[P[ULONG], SAL("_Out_")],
                    Seed: Annotated[P[CHAR], SAL("_Out_")]
                    ):
    raise NotImplementedError()

@syscall
def ZwAllocateVirtualMemory(dp: Dumpulator,
                            ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                            BaseAddress: Annotated[P[PVOID], SAL("_Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize))")],
                            ZeroBits: Annotated[ULONG_PTR, SAL("_In_")],
                            RegionSize: Annotated[P[SIZE_T], SAL("_Inout_")],
                            AllocationType: Annotated[ULONG, SAL("_In_")],
                            Protect: Annotated[ULONG, SAL("_In_")]
                            ):
    assert ZeroBits == 0
    assert ProcessHandle == dp.NtCurrentProcess()
    base = dp.read_ptr(BaseAddress.ptr)
    assert base & 0xFFF == 0
    size = round_to_pages(dp.read_ptr(RegionSize.ptr))
    assert size != 0
    protect = MemoryProtect(Protect)
    if AllocationType == MEM_COMMIT:
        if base == 0:
            base = dp.memory.find_free(size)
            dp.memory.reserve(base, size, protect)
            BaseAddress.write_ptr(base)
            RegionSize.write_ptr(size)
        print(f"commit({hex(base)}[{hex(size)}], {protect})")
        dp.memory.commit(base, size, protect)
    elif AllocationType == MEM_RESERVE:
        if base == 0:
            base = dp.memory.find_free(size)
            BaseAddress.write_ptr(base)
            RegionSize.write_ptr(size)
        print(f"reserve({hex(base)}[{hex(size)}], {protect})")
        dp.memory.reserve(base, size, protect)
    elif AllocationType == MEM_COMMIT | MEM_RESERVE:
        if base == 0:
            base = dp.memory.find_free(size)
            BaseAddress.write_ptr(base)
            RegionSize.write_ptr(size)
        print(f"reserve+commit({hex(base)}[{hex(size)}], {protect})")
        dp.memory.reserve(base, size, protect)
        dp.memory.commit(base, size)
    else:
        raise NotImplementedError()
    return STATUS_SUCCESS

@syscall
def ZwAlpcAcceptConnectPort(dp: Dumpulator,
                            PortHandle: Annotated[P[HANDLE], SAL("_Out_")],
                            ConnectionPortHandle: Annotated[HANDLE, SAL("_In_")],
                            Flags: Annotated[ULONG, SAL("_In_")],
                            ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                            PortAttributes: Annotated[P[ALPC_PORT_ATTRIBUTES], SAL("_In_opt_")],
                            PortContext: Annotated[PVOID, SAL("_In_opt_")],
                            ConnectionRequest: Annotated[P[PORT_MESSAGE], SAL("_In_reads_bytes_(ConnectionRequest->u1.s1.TotalLength)")],
                            ConnectionMessageAttributes: Annotated[P[ALPC_MESSAGE_ATTRIBUTES], SAL("_Inout_opt_")],
                            AcceptConnection: Annotated[BOOLEAN, SAL("_In_")]
                            ):
    raise NotImplementedError()

@syscall
def ZwAlpcCancelMessage(dp: Dumpulator,
                        PortHandle: Annotated[HANDLE, SAL("_In_")],
                        Flags: Annotated[ULONG, SAL("_In_")],
                        MessageContext: Annotated[P[ALPC_CONTEXT_ATTR], SAL("_In_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwAlpcConnectPort(dp: Dumpulator,
                      PortHandle: Annotated[P[HANDLE], SAL("_Out_")],
                      PortName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                      ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                      PortAttributes: Annotated[P[ALPC_PORT_ATTRIBUTES], SAL("_In_opt_")],
                      Flags: Annotated[ULONG, SAL("_In_")],
                      RequiredServerSid: Annotated[PSID, SAL("_In_opt_")],
                      ConnectionMessage: Annotated[P[PORT_MESSAGE], SAL("_Inout_updates_bytes_to_opt_(*BufferLength, *BufferLength)")],
                      BufferLength: Annotated[P[ULONG], SAL("_Inout_opt_")],
                      OutMessageAttributes: Annotated[P[ALPC_MESSAGE_ATTRIBUTES], SAL("_Inout_opt_")],
                      InMessageAttributes: Annotated[P[ALPC_MESSAGE_ATTRIBUTES], SAL("_Inout_opt_")],
                      Timeout: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                      ):
    raise NotImplementedError()

@syscall
def ZwAlpcConnectPortEx(dp: Dumpulator,
                        PortHandle: Annotated[P[HANDLE], SAL("_Out_")],
                        ConnectionPortObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
                        ClientPortObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                        PortAttributes: Annotated[P[ALPC_PORT_ATTRIBUTES], SAL("_In_opt_")],
                        Flags: Annotated[ULONG, SAL("_In_")],
                        ServerSecurityRequirements: Annotated[P[SECURITY_DESCRIPTOR], SAL("_In_opt_")],
                        ConnectionMessage: Annotated[P[PORT_MESSAGE], SAL("_Inout_updates_bytes_to_opt_(*BufferLength, *BufferLength)")],
                        BufferLength: Annotated[P[SIZE_T], SAL("_Inout_opt_")],
                        OutMessageAttributes: Annotated[P[ALPC_MESSAGE_ATTRIBUTES], SAL("_Inout_opt_")],
                        InMessageAttributes: Annotated[P[ALPC_MESSAGE_ATTRIBUTES], SAL("_Inout_opt_")],
                        Timeout: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwAlpcCreatePort(dp: Dumpulator,
                     PortHandle: Annotated[P[HANDLE], SAL("_Out_")],
                     ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                     PortAttributes: Annotated[P[ALPC_PORT_ATTRIBUTES], SAL("_In_opt_")]
                     ):
    raise NotImplementedError()

@syscall
def ZwAlpcCreatePortSection(dp: Dumpulator,
                            PortHandle: Annotated[HANDLE, SAL("_In_")],
                            Flags: Annotated[ULONG, SAL("_In_")],
                            SectionHandle: Annotated[HANDLE, SAL("_In_opt_")],
                            SectionSize: Annotated[SIZE_T, SAL("_In_")],
                            AlpcSectionHandle: Annotated[P[ALPC_HANDLE], SAL("_Out_")],
                            ActualSectionSize: Annotated[P[SIZE_T], SAL("_Out_")]
                            ):
    raise NotImplementedError()

@syscall
def ZwAlpcCreateResourceReserve(dp: Dumpulator,
                                PortHandle: Annotated[HANDLE, SAL("_In_")],
                                Flags: Annotated[ULONG, SAL("_Reserved_")],
                                MessageSize: Annotated[SIZE_T, SAL("_In_")],
                                ResourceId: Annotated[P[ALPC_HANDLE], SAL("_Out_")]
                                ):
    raise NotImplementedError()

@syscall
def ZwAlpcCreateSectionView(dp: Dumpulator,
                            PortHandle: Annotated[HANDLE, SAL("_In_")],
                            Flags: Annotated[ULONG, SAL("_Reserved_")],
                            ViewAttributes: Annotated[P[ALPC_DATA_VIEW_ATTR], SAL("_Inout_")]
                            ):
    raise NotImplementedError()

@syscall
def ZwAlpcCreateSecurityContext(dp: Dumpulator,
                                PortHandle: Annotated[HANDLE, SAL("_In_")],
                                Flags: Annotated[ULONG, SAL("_Reserved_")],
                                SecurityAttribute: Annotated[P[ALPC_SECURITY_ATTR], SAL("_Inout_")]
                                ):
    raise NotImplementedError()

@syscall
def ZwAlpcDeletePortSection(dp: Dumpulator,
                            PortHandle: Annotated[HANDLE, SAL("_In_")],
                            Flags: Annotated[ULONG, SAL("_Reserved_")],
                            SectionHandle: Annotated[ALPC_HANDLE, SAL("_In_")]
                            ):
    raise NotImplementedError()

@syscall
def ZwAlpcDeleteResourceReserve(dp: Dumpulator,
                                PortHandle: Annotated[HANDLE, SAL("_In_")],
                                Flags: Annotated[ULONG, SAL("_Reserved_")],
                                ResourceId: Annotated[ALPC_HANDLE, SAL("_In_")]
                                ):
    raise NotImplementedError()

@syscall
def ZwAlpcDeleteSectionView(dp: Dumpulator,
                            PortHandle: Annotated[HANDLE, SAL("_In_")],
                            Flags: Annotated[ULONG, SAL("_Reserved_")],
                            ViewBase: Annotated[PVOID, SAL("_In_")]
                            ):
    raise NotImplementedError()

@syscall
def ZwAlpcDeleteSecurityContext(dp: Dumpulator,
                                PortHandle: Annotated[HANDLE, SAL("_In_")],
                                Flags: Annotated[ULONG, SAL("_Reserved_")],
                                ContextHandle: Annotated[ALPC_HANDLE, SAL("_In_")]
                                ):
    raise NotImplementedError()

@syscall
def ZwAlpcDisconnectPort(dp: Dumpulator,
                         PortHandle: Annotated[HANDLE, SAL("_In_")],
                         Flags: Annotated[ULONG, SAL("_In_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwAlpcImpersonateClientContainerOfPort(dp: Dumpulator,
                                           PortHandle: Annotated[HANDLE, SAL("_In_")],
                                           Message: Annotated[P[PORT_MESSAGE], SAL("_In_")],
                                           Flags: Annotated[ULONG, SAL("_In_")]
                                           ):
    raise NotImplementedError()

@syscall
def ZwAlpcImpersonateClientOfPort(dp: Dumpulator,
                                  PortHandle: Annotated[HANDLE, SAL("_In_")],
                                  Message: Annotated[P[PORT_MESSAGE], SAL("_In_")],
                                  Flags: Annotated[PVOID, SAL("_In_")]
                                  ):
    raise NotImplementedError()

@syscall
def ZwAlpcOpenSenderProcess(dp: Dumpulator,
                            ProcessHandle: Annotated[P[HANDLE], SAL("_Out_")],
                            PortHandle: Annotated[HANDLE, SAL("_In_")],
                            PortMessage: Annotated[P[PORT_MESSAGE], SAL("_In_")],
                            Flags: Annotated[ULONG, SAL("_In_")],
                            DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                            ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")]
                            ):
    raise NotImplementedError()

@syscall
def ZwAlpcOpenSenderThread(dp: Dumpulator,
                           ThreadHandle: Annotated[P[HANDLE], SAL("_Out_")],
                           PortHandle: Annotated[HANDLE, SAL("_In_")],
                           PortMessage: Annotated[P[PORT_MESSAGE], SAL("_In_")],
                           Flags: Annotated[ULONG, SAL("_In_")],
                           DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                           ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")]
                           ):
    raise NotImplementedError()

@syscall
def ZwAlpcQueryInformation(dp: Dumpulator,
                           PortHandle: Annotated[HANDLE, SAL("_In_opt_")],
                           PortInformationClass: Annotated[ALPC_PORT_INFORMATION_CLASS, SAL("_In_")],
                           PortInformation: Annotated[PVOID, SAL("_Inout_updates_bytes_to_(Length, *ReturnLength)")],
                           Length: Annotated[ULONG, SAL("_In_")],
                           ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                           ):
    raise NotImplementedError()

@syscall
def ZwAlpcQueryInformationMessage(dp: Dumpulator,
                                  PortHandle: Annotated[HANDLE, SAL("_In_")],
                                  PortMessage: Annotated[P[PORT_MESSAGE], SAL("_In_")],
                                  MessageInformationClass: Annotated[ALPC_MESSAGE_INFORMATION_CLASS, SAL("_In_")],
                                  MessageInformation: Annotated[PVOID, SAL("_Out_writes_bytes_to_opt_(Length, *ReturnLength)")],
                                  Length: Annotated[ULONG, SAL("_In_")],
                                  ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                                  ):
    raise NotImplementedError()

@syscall
def ZwAlpcRevokeSecurityContext(dp: Dumpulator,
                                PortHandle: Annotated[HANDLE, SAL("_In_")],
                                Flags: Annotated[ULONG, SAL("_Reserved_")],
                                ContextHandle: Annotated[ALPC_HANDLE, SAL("_In_")]
                                ):
    raise NotImplementedError()

@syscall
def ZwAlpcSendWaitReceivePort(dp: Dumpulator,
                              PortHandle: Annotated[HANDLE, SAL("_In_")],
                              Flags: Annotated[ULONG, SAL("_In_")],
                              SendMessageA: Annotated[P[PORT_MESSAGE], SAL("_In_reads_bytes_opt_(SendMessage->u1.s1.TotalLength)")],
                              SendMessageAttributes: Annotated[P[ALPC_MESSAGE_ATTRIBUTES], SAL("_Inout_opt_")],
                              ReceiveMessage: Annotated[P[PORT_MESSAGE], SAL("_Out_writes_bytes_to_opt_(*BufferLength, *BufferLength)")],
                              BufferLength: Annotated[P[SIZE_T], SAL("_Inout_opt_")],
                              ReceiveMessageAttributes: Annotated[P[ALPC_MESSAGE_ATTRIBUTES], SAL("_Inout_opt_")],
                              Timeout: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                              ):
    raise NotImplementedError()

@syscall
def ZwAlpcSetInformation(dp: Dumpulator,
                         PortHandle: Annotated[HANDLE, SAL("_In_")],
                         PortInformationClass: Annotated[ALPC_PORT_INFORMATION_CLASS, SAL("_In_")],
                         PortInformation: Annotated[PVOID, SAL("_In_reads_bytes_opt_(Length)")],
                         Length: Annotated[ULONG, SAL("_In_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwAreMappedFilesTheSame(dp: Dumpulator,
                            File1MappedAsAnImage: Annotated[PVOID, SAL("_In_")],
                            File2MappedAsFile: Annotated[PVOID, SAL("_In_")]
                            ):
    raise NotImplementedError()

@syscall
def ZwAssignProcessToJobObject(dp: Dumpulator,
                               JobHandle: Annotated[HANDLE, SAL("_In_")],
                               ProcessHandle: Annotated[HANDLE, SAL("_In_")]
                               ):
    raise NotImplementedError()

@syscall
def ZwAssociateWaitCompletionPacket(dp: Dumpulator,
                                    WaitCompletionPacketHandle: Annotated[HANDLE, SAL("_In_")],
                                    IoCompletionHandle: Annotated[HANDLE, SAL("_In_")],
                                    TargetObjectHandle: Annotated[HANDLE, SAL("_In_")],
                                    KeyContext: Annotated[PVOID, SAL("_In_opt_")],
                                    ApcContext: Annotated[PVOID, SAL("_In_opt_")],
                                    IoStatus: Annotated[NTSTATUS, SAL("_In_")],
                                    IoStatusInformation: Annotated[ULONG_PTR, SAL("_In_")],
                                    AlreadySignaled: Annotated[P[BOOLEAN], SAL("_Out_opt_")]
                                    ):
    raise NotImplementedError()

@syscall
def ZwCallbackReturn(dp: Dumpulator,
                     OutputBuffer: Annotated[PVOID, SAL("_In_reads_bytes_opt_(OutputLength)")],
                     OutputLength: Annotated[ULONG, SAL("_In_")],
                     Status: Annotated[NTSTATUS, SAL("_In_")]
                     ):
    raise NotImplementedError()

@syscall
def ZwCallEnclave(dp: Dumpulator,
                  Routine: Annotated[P[ENCLAVE_ROUTINE], SAL("_In_")],
                  Parameter: Annotated[PVOID, SAL("_In_")],
                  WaitForThread: Annotated[BOOLEAN, SAL("_In_")],
                  ReturnValue: Annotated[P[PVOID], SAL("_Out_opt_")]
                  ):
    raise NotImplementedError()

@syscall
def ZwCancelIoFile(dp: Dumpulator,
                   FileHandle: Annotated[HANDLE, SAL("_In_")],
                   IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")]
                   ):
    raise NotImplementedError()

@syscall
def ZwCancelIoFileEx(dp: Dumpulator,
                     FileHandle: Annotated[HANDLE, SAL("_In_")],
                     IoRequestToCancel: Annotated[P[IO_STATUS_BLOCK], SAL("_In_opt_")],
                     IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")]
                     ):
    raise NotImplementedError()

@syscall
def ZwCancelSynchronousIoFile(dp: Dumpulator,
                              ThreadHandle: Annotated[HANDLE, SAL("_In_")],
                              IoRequestToCancel: Annotated[P[IO_STATUS_BLOCK], SAL("_In_opt_")],
                              IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")]
                              ):
    raise NotImplementedError()

@syscall
def ZwCancelTimer(dp: Dumpulator,
                  TimerHandle: Annotated[HANDLE, SAL("_In_")],
                  CurrentState: Annotated[P[BOOLEAN], SAL("_Out_opt_")]
                  ):
    raise NotImplementedError()

@syscall
def ZwCancelTimer2(dp: Dumpulator,
                   TimerHandle: Annotated[HANDLE, SAL("_In_")],
                   Parameters: Annotated[P[T2_CANCEL_PARAMETERS], SAL("_In_")]
                   ):
    raise NotImplementedError()

@syscall
def ZwCancelWaitCompletionPacket(dp: Dumpulator,
                                 WaitCompletionPacketHandle: Annotated[HANDLE, SAL("_In_")],
                                 RemoveSignaledPacket: Annotated[BOOLEAN, SAL("_In_")]
                                 ):
    raise NotImplementedError()

@syscall
def ZwChangeProcessState(dp: Dumpulator,
                         ProcessStateChangeHandle: Annotated[HANDLE, SAL("_In_")],
                         ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                         StateChangeType: Annotated[PROCESS_STATE_CHANGE_TYPE, SAL("_In_")],
                         ExtendedInformation: Annotated[PVOID, SAL("_In_opt_")],
                         ExtendedInformationLength: Annotated[SIZE_T, SAL("_In_opt_")],
                         Reserved: Annotated[ULONG64, SAL("_In_opt_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwChangeThreadState(dp: Dumpulator,
                        ThreadStateChangeHandle: Annotated[HANDLE, SAL("_In_")],
                        ThreadHandle: Annotated[HANDLE, SAL("_In_")],
                        StateChangeType: Annotated[THREAD_STATE_CHANGE_TYPE, SAL("_In_")],
                        ExtendedInformation: Annotated[PVOID, SAL("_In_opt_")],
                        ExtendedInformationLength: Annotated[SIZE_T, SAL("_In_opt_")],
                        Reserved: Annotated[ULONG64, SAL("_In_opt_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwClearEvent(dp: Dumpulator,
                 EventHandle: Annotated[HANDLE, SAL("_In_")]
                 ):
    raise NotImplementedError()

@syscall
def ZwClose(dp: Dumpulator,
            Handle: Annotated[HANDLE, SAL("_In_ _Post_ptr_invalid_")]
            ):
    if dp.handles.valid(Handle):
        dp.handles.close(Handle)
        return STATUS_SUCCESS
    return STATUS_INVALID_HANDLE

@syscall
def ZwCloseObjectAuditAlarm(dp: Dumpulator,
                            SubsystemName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                            HandleId: Annotated[PVOID, SAL("_In_opt_")],
                            GenerateOnClose: Annotated[BOOLEAN, SAL("_In_")]
                            ):
    raise NotImplementedError()

@syscall
def ZwCommitComplete(dp: Dumpulator,
                     EnlistmentHandle: Annotated[HANDLE, SAL("_In_")],
                     TmVirtualClock: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                     ):
    raise NotImplementedError()

@syscall
def ZwCommitEnlistment(dp: Dumpulator,
                       EnlistmentHandle: Annotated[HANDLE, SAL("_In_")],
                       TmVirtualClock: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                       ):
    raise NotImplementedError()

@syscall
def ZwCommitTransaction(dp: Dumpulator,
                        TransactionHandle: Annotated[HANDLE, SAL("_In_")],
                        Wait: Annotated[BOOLEAN, SAL("_In_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwCompactKeys(dp: Dumpulator,
                  Count: Annotated[ULONG, SAL("_In_")],
                  KeyArray: Annotated[P[HANDLE], SAL("_In_reads_(Count)")]
                  ):
    raise NotImplementedError()

@syscall
def ZwCompareObjects(dp: Dumpulator,
                     FirstObjectHandle: Annotated[HANDLE, SAL("_In_")],
                     SecondObjectHandle: Annotated[HANDLE, SAL("_In_")]
                     ):
    raise NotImplementedError()

@syscall
def ZwCompareSigningLevels(dp: Dumpulator,
                           FirstSigningLevel: Annotated[SE_SIGNING_LEVEL, SAL("_In_")],
                           SecondSigningLevel: Annotated[SE_SIGNING_LEVEL, SAL("_In_")]
                           ):
    raise NotImplementedError()

@syscall
def ZwCompareTokens(dp: Dumpulator,
                    FirstTokenHandle: Annotated[HANDLE, SAL("_In_")],
                    SecondTokenHandle: Annotated[HANDLE, SAL("_In_")],
                    Equal: Annotated[P[BOOLEAN], SAL("_Out_")]
                    ):
    raise NotImplementedError()

@syscall
def ZwCompleteConnectPort(dp: Dumpulator,
                          PortHandle: Annotated[HANDLE, SAL("_In_")]
                          ):
    raise NotImplementedError()

@syscall
def ZwCompressKey(dp: Dumpulator,
                  Key: Annotated[HANDLE, SAL("_In_")]
                  ):
    raise NotImplementedError()

@syscall
def ZwConnectPort(dp: Dumpulator,
                  PortHandle: Annotated[P[HANDLE], SAL("_Out_")],
                  PortName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                  SecurityQos: Annotated[P[SECURITY_QUALITY_OF_SERVICE], SAL("_In_")],
                  ClientView: Annotated[P[PORT_VIEW], SAL("_Inout_opt_")],
                  ServerView: Annotated[P[REMOTE_PORT_VIEW], SAL("_Inout_opt_")],
                  MaxMessageLength: Annotated[P[ULONG], SAL("_Out_opt_")],
                  ConnectionInformation: Annotated[PVOID, SAL("_Inout_updates_bytes_to_opt_(*ConnectionInformationLength, *ConnectionInformationLength)")],
                  ConnectionInformationLength: Annotated[P[ULONG], SAL("_Inout_opt_")]
                  ):
    raise NotImplementedError()

@syscall
def ZwContinue(dp: Dumpulator,
               ContextRecord: Annotated[P[CONTEXT], SAL("_In_")],
               TestAlert: Annotated[BOOLEAN, SAL("_In_")]
               ):
    # Trigger a context switch
    assert not TestAlert

    # TODO: move this to a dedicated helper method
    from .dumpulator import UnicornExceptionInfo, ExceptionType
    exception = UnicornExceptionInfo()
    exception.type = ExceptionType.ContextSwitch
    exception.final = True
    context_type = CONTEXT if dp.ptr_size() == 8 else WOW64_CONTEXT
    context_size = ctypes.sizeof(context_type)
    data = dp.read(ContextRecord.ptr, context_size)
    context = context_type.from_buffer(data)
    context.to_regs(dp.regs)
    # Modifying fs/gs also appears to reset fs_base/gs_base
    if dp.x64:
        dp.regs.gs_base = dp.teb
    else:
        dp.regs.fs_base = dp.teb
        dp.regs.gs_base = dp.teb - 2 * PAGE_SIZE
    exception.context = dp._uc.context_save()
    return exception

@syscall
def ZwContinueEx(dp: Dumpulator,
                 ContextRecord: Annotated[P[CONTEXT], SAL("_In_")],
                 ContinueArgument: Annotated[PVOID, SAL("_In_", "PKCONTINUE_ARGUMENT and BOOLEAN are valid")]
                 ):
    raise NotImplementedError()

@syscall
def ZwCreateDebugObject(dp: Dumpulator,
                        DebugObjectHandle: Annotated[P[HANDLE], SAL("_Out_")],
                        DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                        ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                        Flags: Annotated[ULONG, SAL("_In_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwCreateDirectoryObject(dp: Dumpulator,
                            DirectoryHandle: Annotated[P[HANDLE], SAL("_Out_")],
                            DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                            ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")]
                            ):
    raise NotImplementedError()

@syscall
def ZwCreateDirectoryObjectEx(dp: Dumpulator,
                              DirectoryHandle: Annotated[P[HANDLE], SAL("_Out_")],
                              DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                              ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
                              ShadowDirectoryHandle: Annotated[HANDLE, SAL("_In_")],
                              Flags: Annotated[ULONG, SAL("_In_")]
                              ):
    raise NotImplementedError()

@syscall
def ZwCreateEnclave(dp: Dumpulator,
                    ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                    BaseAddress: Annotated[P[PVOID], SAL("_Inout_")],
                    ZeroBits: Annotated[ULONG_PTR, SAL("_In_")],
                    Size: Annotated[SIZE_T, SAL("_In_")],
                    InitialCommitment: Annotated[SIZE_T, SAL("_In_")],
                    EnclaveType: Annotated[ULONG, SAL("_In_")],
                    EnclaveInformation: Annotated[PVOID, SAL("_In_reads_bytes_(EnclaveInformationLength)")],
                    EnclaveInformationLength: Annotated[ULONG, SAL("_In_")],
                    EnclaveError: Annotated[P[ULONG], SAL("_Out_opt_")]
                    ):
    raise NotImplementedError()

@syscall
def ZwCreateEnlistment(dp: Dumpulator,
                       EnlistmentHandle: Annotated[P[HANDLE], SAL("_Out_")],
                       DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                       ResourceManagerHandle: Annotated[HANDLE, SAL("_In_")],
                       TransactionHandle: Annotated[HANDLE, SAL("_In_")],
                       ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                       CreateOptions: Annotated[ULONG, SAL("_In_opt_")],
                       NotificationMask: Annotated[NOTIFICATION_MASK, SAL("_In_")],
                       EnlistmentKey: Annotated[PVOID, SAL("_In_opt_")]
                       ):
    raise NotImplementedError()

@syscall
def ZwCreateEvent(dp: Dumpulator,
                  EventHandle: Annotated[P[HANDLE], SAL("_Out_")],
                  DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                  ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                  EventType: Annotated[EVENT_TYPE, SAL("_In_")],
                  InitialState: Annotated[BOOLEAN, SAL("_In_")]
                  ):
    assert DesiredAccess == 0x1f0003
    if ObjectAttributes != 0:
        attributes = ObjectAttributes[0]
        assert attributes.ObjectName == 0
        assert attributes.RootDirectory == 0
        assert attributes.SecurityDescriptor == 0
        assert attributes.SecurityQualityOfService == 0
        assert attributes.Attributes == 2  # OBJ_INHERIT
    event = EventObject(EventType, InitialState != 0)
    handle = dp.handles.new(event)
    EventHandle.write_ptr(handle)
    return STATUS_SUCCESS

@syscall
def ZwCreateEventPair(dp: Dumpulator,
                      EventPairHandle: Annotated[P[HANDLE], SAL("_Out_")],
                      DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                      ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")]
                      ):
    raise NotImplementedError()

@syscall
def ZwCreateFile(dp: Dumpulator,
                 FileHandle: Annotated[P[HANDLE], SAL("_Out_")],
                 DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                 ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
                 IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                 AllocationSize: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")],
                 FileAttributes: Annotated[ULONG, SAL("_In_")],
                 ShareAccess: Annotated[ULONG, SAL("_In_")],
                 CreateDisposition: Annotated[ULONG, SAL("_In_")],
                 CreateOptions: Annotated[ULONG, SAL("_In_")],
                 EaBuffer: Annotated[PVOID, SAL("_In_reads_bytes_opt_(EaLength)")],
                 EaLength: Annotated[ULONG, SAL("_In_")]
                 ):
    assert ObjectAttributes.ptr != 0
    file_name = ObjectAttributes[0].ObjectName[0].read_str()
    print(f"create/open {file_name}")
    assert FileHandle.ptr != 0
    assert IoStatusBlock.ptr != 0
    #assert EaBuffer.ptr == 0
    #assert EaLength == 0

    if file_name == "\\Device\\ConDrv\\Server":
        assert DesiredAccess == 0x12019f
        assert AllocationSize.ptr == 0x0
        assert FileAttributes == 0x0
        assert ShareAccess == 0x7
        assert CreateDisposition == 0x2
        assert CreateOptions == 0
        handle = dp.console_handle
        if handle == 0:
            handle = dp.handles.new(None)
            dp.console_handle = handle
        elif not dp.handles.valid(handle):
            dp.handles.add(handle, None)
        FileHandle.write_ptr(handle)
        IO_STATUS_BLOCK.write(IoStatusBlock, STATUS_SUCCESS, FILE_OPENED)
        return STATUS_SUCCESS
    elif file_name == "\\Reference":
        handle = dp.handles.new(FileHandle(file_name))
        FileHandle.write_ptr(handle)
        IO_STATUS_BLOCK.write(IoStatusBlock, STATUS_SUCCESS, FILE_OPENED)
        return STATUS_SUCCESS
    elif file_name == "\\Connect":
        handle = dp.handles.new(FileHandle(file_name))
        FileHandle.write_ptr(handle)
        IO_STATUS_BLOCK.write(IoStatusBlock, STATUS_SUCCESS, FILE_OPENED)
        return STATUS_SUCCESS
    elif file_name == "\\Input":
        handle = dp.console_handle
        if handle == 0:
            handle = dp.handles.new(None)
            dp.stdin_handle = handle
        elif not dp.handles.valid(handle):
            dp.handles.add(handle, None)
        FileHandle.write_ptr(handle)
        IO_STATUS_BLOCK.write(IoStatusBlock, STATUS_SUCCESS, FILE_OPENED)
        return STATUS_SUCCESS
    elif file_name == "\\Output":
        handle = dp.console_handle
        if handle == 0:
            handle = dp.handles.new(None)
            dp.stdout_handle = handle
        elif not dp.handles.valid(handle):
            dp.handles.add(handle, None)
        FileHandle.write_ptr(handle)
        IO_STATUS_BLOCK.write(IoStatusBlock, STATUS_SUCCESS, FILE_OPENED)
        return STATUS_SUCCESS
    else:
        handle = dp.handles.open_file(file_name)
        if handle is None:
            return STATUS_NO_SUCH_FILE
        print(f"Created handle {hex(handle)}")
        FileHandle.write_ptr(handle)
        IO_STATUS_BLOCK.write(IoStatusBlock, STATUS_SUCCESS, FILE_OPENED)
        return STATUS_SUCCESS

@syscall
def ZwCreateIoCompletion(dp: Dumpulator,
                         IoCompletionHandle: Annotated[P[HANDLE], SAL("_Out_")],
                         DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                         ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                         Count: Annotated[ULONG, SAL("_In_opt_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwCreateIRTimer(dp: Dumpulator,
                    TimerHandle: Annotated[P[HANDLE], SAL("_Out_")],
                    DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")]
                    ):
    raise NotImplementedError()

@syscall
def ZwCreateJobObject(dp: Dumpulator,
                      JobHandle: Annotated[P[HANDLE], SAL("_Out_")],
                      DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                      ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")]
                      ):
    raise NotImplementedError()

@syscall
def ZwCreateJobSet(dp: Dumpulator,
                   NumJob: Annotated[ULONG, SAL("_In_")],
                   UserJobSet: Annotated[P[JOB_SET_ARRAY], SAL("_In_reads_(NumJob)")],
                   Flags: Annotated[ULONG, SAL("_In_")]
                   ):
    raise NotImplementedError()

@syscall
def ZwCreateKey(dp: Dumpulator,
                KeyHandle: Annotated[P[HANDLE], SAL("_Out_")],
                DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
                TitleIndex: Annotated[ULONG, SAL("_Reserved_")],
                Class: Annotated[P[UNICODE_STRING], SAL("_In_opt_")],
                CreateOptions: Annotated[ULONG, SAL("_In_")],
                Disposition: Annotated[P[ULONG], SAL("_Out_opt_")]
                ):
    raise NotImplementedError()

@syscall
def ZwCreateKeyedEvent(dp: Dumpulator,
                       KeyedEventHandle: Annotated[P[HANDLE], SAL("_Out_")],
                       DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                       ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                       Flags: Annotated[ULONG, SAL("_In_")]
                       ):
    raise NotImplementedError()

@syscall
def ZwCreateKeyTransacted(dp: Dumpulator,
                          KeyHandle: Annotated[P[HANDLE], SAL("_Out_")],
                          DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                          ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
                          TitleIndex: Annotated[ULONG, SAL("_Reserved_")],
                          Class: Annotated[P[UNICODE_STRING], SAL("_In_opt_")],
                          CreateOptions: Annotated[ULONG, SAL("_In_")],
                          TransactionHandle: Annotated[HANDLE, SAL("_In_")],
                          Disposition: Annotated[P[ULONG], SAL("_Out_opt_")]
                          ):
    raise NotImplementedError()

@syscall
def ZwCreateLowBoxToken(dp: Dumpulator,
                        TokenHandle: Annotated[P[HANDLE], SAL("_Out_")],
                        ExistingTokenHandle: Annotated[HANDLE, SAL("_In_")],
                        DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                        ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                        PackageSid: Annotated[PSID, SAL("_In_")],
                        CapabilityCount: Annotated[ULONG, SAL("_In_")],
                        Capabilities: Annotated[P[SID_AND_ATTRIBUTES], SAL("_In_reads_opt_(CapabilityCount)")],
                        HandleCount: Annotated[ULONG, SAL("_In_")],
                        Handles: Annotated[P[HANDLE], SAL("_In_reads_opt_(HandleCount)")]
                        ):
    raise NotImplementedError()

@syscall
def ZwCreateMailslotFile(dp: Dumpulator,
                         FileHandle: Annotated[P[HANDLE], SAL("_Out_")],
                         DesiredAccess: Annotated[ULONG, SAL("_In_")],
                         ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
                         IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                         CreateOptions: Annotated[ULONG, SAL("_In_")],
                         MailslotQuota: Annotated[ULONG, SAL("_In_")],
                         MaximumMessageSize: Annotated[ULONG, SAL("_In_")],
                         ReadTimeout: Annotated[P[LARGE_INTEGER], SAL("_In_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwCreateMutant(dp: Dumpulator,
                   MutantHandle: Annotated[P[HANDLE], SAL("_Out_")],
                   DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                   ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                   InitialOwner: Annotated[BOOLEAN, SAL("_In_")]
                   ):
    raise NotImplementedError()

@syscall
def ZwCreateNamedPipeFile(dp: Dumpulator,
                          FileHandle: Annotated[P[HANDLE], SAL("_Out_")],
                          DesiredAccess: Annotated[ULONG, SAL("_In_")],
                          ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
                          IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                          ShareAccess: Annotated[ULONG, SAL("_In_")],
                          CreateDisposition: Annotated[ULONG, SAL("_In_")],
                          CreateOptions: Annotated[ULONG, SAL("_In_")],
                          NamedPipeType: Annotated[ULONG, SAL("_In_")],
                          ReadMode: Annotated[ULONG, SAL("_In_")],
                          CompletionMode: Annotated[ULONG, SAL("_In_")],
                          MaximumInstances: Annotated[ULONG, SAL("_In_")],
                          InboundQuota: Annotated[ULONG, SAL("_In_")],
                          OutboundQuota: Annotated[ULONG, SAL("_In_")],
                          DefaultTimeout: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                          ):
    raise NotImplementedError()

@syscall
def ZwCreatePagingFile(dp: Dumpulator,
                       PageFileName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                       MinimumSize: Annotated[P[LARGE_INTEGER], SAL("_In_")],
                       MaximumSize: Annotated[P[LARGE_INTEGER], SAL("_In_")],
                       Priority: Annotated[ULONG, SAL("_In_")]
                       ):
    raise NotImplementedError()

@syscall
def ZwCreatePartition(dp: Dumpulator,
                      ParentPartitionHandle: Annotated[HANDLE, SAL("_In_")],
                      PartitionHandle: Annotated[P[HANDLE], SAL("_Out_")],
                      DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                      ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                      PreferredNode: Annotated[ULONG, SAL("_In_")]
                      ):
    raise NotImplementedError()

@syscall
def ZwCreatePort(dp: Dumpulator,
                 PortHandle: Annotated[P[HANDLE], SAL("_Out_")],
                 ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                 MaxConnectionInfoLength: Annotated[ULONG, SAL("_In_")],
                 MaxMessageLength: Annotated[ULONG, SAL("_In_")],
                 MaxPoolUsage: Annotated[ULONG, SAL("_In_opt_")]
                 ):
    raise NotImplementedError()

@syscall
def ZwCreatePrivateNamespace(dp: Dumpulator,
                             NamespaceHandle: Annotated[P[HANDLE], SAL("_Out_")],
                             DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                             ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                             BoundaryDescriptor: Annotated[P[OBJECT_BOUNDARY_DESCRIPTOR], SAL("_In_")]
                             ):
    raise NotImplementedError()

@syscall
def ZwCreateProcess(dp: Dumpulator,
                    ProcessHandle: Annotated[P[HANDLE], SAL("_Out_")],
                    DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                    ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                    ParentProcess: Annotated[HANDLE, SAL("_In_")],
                    InheritObjectTable: Annotated[BOOLEAN, SAL("_In_")],
                    SectionHandle: Annotated[HANDLE, SAL("_In_opt_")],
                    DebugPort: Annotated[HANDLE, SAL("_In_opt_")],
                    TokenHandle: Annotated[HANDLE, SAL("_In_opt_")]
                    ):
    raise NotImplementedError()

@syscall
def ZwCreateProcessEx(dp: Dumpulator,
                      ProcessHandle: Annotated[P[HANDLE], SAL("_Out_")],
                      DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                      ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                      ParentProcess: Annotated[HANDLE, SAL("_In_")],
                      Flags: Annotated[ULONG, SAL("_In_", "PROCESS_CREATE_FLAGS_*")],
                      SectionHandle: Annotated[HANDLE, SAL("_In_opt_")],
                      DebugPort: Annotated[HANDLE, SAL("_In_opt_")],
                      TokenHandle: Annotated[HANDLE, SAL("_In_opt_")],
                      Reserved: Annotated[ULONG, SAL("_Reserved_", "JobMemberLevel")]
                      ):
    raise NotImplementedError()

@syscall
def ZwCreateProcessStateChange(dp: Dumpulator,
                               ProcessStateChangeHandle: Annotated[P[HANDLE], SAL("_Out_")],
                               DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                               ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                               ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                               Reserved: Annotated[ULONG64, SAL("_In_opt_")]
                               ):
    raise NotImplementedError()

@syscall
def ZwCreateProfile(dp: Dumpulator,
                    ProfileHandle: Annotated[P[HANDLE], SAL("_Out_")],
                    Process: Annotated[HANDLE, SAL("_In_opt_")],
                    ProfileBase: Annotated[PVOID, SAL("_In_")],
                    ProfileSize: Annotated[SIZE_T, SAL("_In_")],
                    BucketSize: Annotated[ULONG, SAL("_In_")],
                    Buffer: Annotated[P[ULONG], SAL("_In_reads_bytes_(BufferSize)")],
                    BufferSize: Annotated[ULONG, SAL("_In_")],
                    ProfileSource: Annotated[KPROFILE_SOURCE, SAL("_In_")],
                    Affinity: Annotated[KAFFINITY, SAL("_In_")]
                    ):
    raise NotImplementedError()

@syscall
def ZwCreateProfileEx(dp: Dumpulator,
                      ProfileHandle: Annotated[P[HANDLE], SAL("_Out_")],
                      Process: Annotated[HANDLE, SAL("_In_opt_")],
                      ProfileBase: Annotated[PVOID, SAL("_In_")],
                      ProfileSize: Annotated[SIZE_T, SAL("_In_")],
                      BucketSize: Annotated[ULONG, SAL("_In_")],
                      Buffer: Annotated[P[ULONG], SAL("_In_reads_bytes_(BufferSize)")],
                      BufferSize: Annotated[ULONG, SAL("_In_")],
                      ProfileSource: Annotated[KPROFILE_SOURCE, SAL("_In_")],
                      GroupCount: Annotated[USHORT, SAL("_In_")],
                      GroupAffinity: Annotated[P[GROUP_AFFINITY], SAL("_In_reads_(GroupCount)")]
                      ):
    raise NotImplementedError()

@syscall
def ZwCreateResourceManager(dp: Dumpulator,
                            ResourceManagerHandle: Annotated[P[HANDLE], SAL("_Out_")],
                            DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                            TmHandle: Annotated[HANDLE, SAL("_In_")],
                            RmGuid: Annotated[P[GUID], SAL("_In_")],
                            ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                            CreateOptions: Annotated[ULONG, SAL("_In_opt_")],
                            Description: Annotated[P[UNICODE_STRING], SAL("_In_opt_")]
                            ):
    raise NotImplementedError()

@syscall
def ZwCreateSection(dp: Dumpulator,
                    SectionHandle: Annotated[P[HANDLE], SAL("_Out_")],
                    DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                    ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                    MaximumSize: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")],
                    SectionPageProtection: Annotated[ULONG, SAL("_In_")],
                    AllocationAttributes: Annotated[ULONG, SAL("_In_")],
                    FileHandle: Annotated[HANDLE, SAL("_In_opt_")]
                    ):
    assert SectionHandle != 0
    assert DesiredAccess == 0xd
    assert ObjectAttributes == 0
    assert MaximumSize == 0
    assert SectionPageProtection == PAGE_EXECUTE
    assert AllocationAttributes == MEM_IMAGE
    file = dp.handles.get(FileHandle, AbstractFileObject)
    assert file is not None
    section_handle = dp.handles.new(SectionObject(file))
    SectionHandle.write_ptr(section_handle)
    return STATUS_SUCCESS

@syscall
def ZwCreateSectionEx(dp: Dumpulator,
                      SectionHandle: Annotated[P[HANDLE], SAL("_Out_")],
                      DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                      ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                      MaximumSize: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")],
                      SectionPageProtection: Annotated[ULONG, SAL("_In_")],
                      AllocationAttributes: Annotated[ULONG, SAL("_In_")],
                      FileHandle: Annotated[HANDLE, SAL("_In_opt_")],
                      ExtendedParameters: Annotated[P[MEM_EXTENDED_PARAMETER], SAL("_Inout_updates_opt_(ExtendedParameterCount)")],
                      ExtendedParameterCount: Annotated[ULONG, SAL("_In_")]
                      ):
    raise NotImplementedError()

@syscall
def ZwCreateSemaphore(dp: Dumpulator,
                      SemaphoreHandle: Annotated[P[HANDLE], SAL("_Out_")],
                      DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                      ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                      InitialCount: Annotated[LONG, SAL("_In_")],
                      MaximumCount: Annotated[LONG, SAL("_In_")]
                      ):
    raise NotImplementedError()

@syscall
def ZwCreateSymbolicLinkObject(dp: Dumpulator,
                               LinkHandle: Annotated[P[HANDLE], SAL("_Out_")],
                               DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                               ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
                               LinkTarget: Annotated[P[UNICODE_STRING], SAL("_In_")]
                               ):
    raise NotImplementedError()

@syscall
def ZwCreateThread(dp: Dumpulator,
                   ThreadHandle: Annotated[P[HANDLE], SAL("_Out_")],
                   DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                   ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                   ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                   ClientId: Annotated[P[CLIENT_ID], SAL("_Out_")],
                   ThreadContext: Annotated[P[CONTEXT], SAL("_In_")],
                   InitialTeb: Annotated[P[INITIAL_TEB], SAL("_In_")],
                   CreateSuspended: Annotated[BOOLEAN, SAL("_In_")]
                   ):
    raise NotImplementedError()

@syscall
def ZwCreateThreadEx(dp: Dumpulator,
                     ThreadHandle: Annotated[P[HANDLE], SAL("_Out_")],
                     DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                     ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                     ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                     StartRoutine: Annotated[PVOID, SAL("_In_", "PUSER_THREAD_START_ROUTINE")],
                     Argument: Annotated[PVOID, SAL("_In_opt_")],
                     CreateFlags: Annotated[ULONG, SAL("_In_", "THREAD_CREATE_FLAGS_*")],
                     ZeroBits: Annotated[SIZE_T, SAL("_In_")],
                     StackSize: Annotated[SIZE_T, SAL("_In_")],
                     MaximumStackSize: Annotated[SIZE_T, SAL("_In_")],
                     AttributeList: Annotated[P[PS_ATTRIBUTE_LIST], SAL("_In_opt_")]
                     ):
    assert DesiredAccess == 0x1fffff
    assert ObjectAttributes == 0
    assert ProcessHandle == dp.NtCurrentProcess()
    assert CreateFlags == 0
    assert ZeroBits == 0
    assert StackSize == 0
    assert MaximumStackSize == 0
    # TODO: sanity check AttributeList
    thread = ThreadObject(StartRoutine.ptr, Argument.ptr)
    handle = dp.handles.new(thread)
    print(f"Started new thread {thread}, handle: {hex(handle)}")
    dp.write_ptr(ThreadHandle, handle)
    return STATUS_SUCCESS

@syscall
def ZwCreateThreadStateChange(dp: Dumpulator,
                              ThreadStateChangeHandle: Annotated[P[HANDLE], SAL("_Out_")],
                              DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                              ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                              ThreadHandle: Annotated[HANDLE, SAL("_In_")],
                              Reserved: Annotated[ULONG64, SAL("_In_opt_")]
                              ):
    raise NotImplementedError()

@syscall
def ZwCreateTimer(dp: Dumpulator,
                  TimerHandle: Annotated[P[HANDLE], SAL("_Out_")],
                  DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                  ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                  TimerType: Annotated[TIMER_TYPE, SAL("_In_")]
                  ):
    raise NotImplementedError()

@syscall
def ZwCreateTimer2(dp: Dumpulator,
                   TimerHandle: Annotated[P[HANDLE], SAL("_Out_")],
                   Reserved1: Annotated[PVOID, SAL("_In_opt_")],
                   ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                   Attributes: Annotated[ULONG, SAL("_In_")],
                   DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")]
                   ):
    raise NotImplementedError()

@syscall
def ZwCreateToken(dp: Dumpulator,
                  TokenHandle: Annotated[P[HANDLE], SAL("_Out_")],
                  DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                  ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                  Type: Annotated[TOKEN_TYPE, SAL("_In_")],
                  AuthenticationId: Annotated[P[LUID], SAL("_In_")],
                  ExpirationTime: Annotated[P[LARGE_INTEGER], SAL("_In_")],
                  User: Annotated[P[TOKEN_USER], SAL("_In_")],
                  Groups: Annotated[P[TOKEN_GROUPS], SAL("_In_")],
                  Privileges: Annotated[P[TOKEN_PRIVILEGES], SAL("_In_")],
                  Owner: Annotated[P[TOKEN_OWNER], SAL("_In_opt_")],
                  PrimaryGroup: Annotated[P[TOKEN_PRIMARY_GROUP], SAL("_In_")],
                  DefaultDacl: Annotated[P[TOKEN_DEFAULT_DACL], SAL("_In_opt_")],
                  Source: Annotated[P[TOKEN_SOURCE], SAL("_In_")]
                  ):
    raise NotImplementedError()

@syscall
def ZwCreateTokenEx(dp: Dumpulator,
                    TokenHandle: Annotated[P[HANDLE], SAL("_Out_")],
                    DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                    ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                    Type: Annotated[TOKEN_TYPE, SAL("_In_")],
                    AuthenticationId: Annotated[P[LUID], SAL("_In_")],
                    ExpirationTime: Annotated[P[LARGE_INTEGER], SAL("_In_")],
                    User: Annotated[P[TOKEN_USER], SAL("_In_")],
                    Groups: Annotated[P[TOKEN_GROUPS], SAL("_In_")],
                    Privileges: Annotated[P[TOKEN_PRIVILEGES], SAL("_In_")],
                    UserAttributes: Annotated[P[TOKEN_SECURITY_ATTRIBUTES_INFORMATION], SAL("_In_opt_")],
                    DeviceAttributes: Annotated[P[TOKEN_SECURITY_ATTRIBUTES_INFORMATION], SAL("_In_opt_")],
                    DeviceGroups: Annotated[P[TOKEN_GROUPS], SAL("_In_opt_")],
                    MandatoryPolicy: Annotated[P[TOKEN_MANDATORY_POLICY], SAL("_In_opt_")],
                    Owner: Annotated[P[TOKEN_OWNER], SAL("_In_opt_")],
                    PrimaryGroup: Annotated[P[TOKEN_PRIMARY_GROUP], SAL("_In_")],
                    DefaultDacl: Annotated[P[TOKEN_DEFAULT_DACL], SAL("_In_opt_")],
                    Source: Annotated[P[TOKEN_SOURCE], SAL("_In_")]
                    ):
    raise NotImplementedError()

@syscall
def ZwCreateTransaction(dp: Dumpulator,
                        TransactionHandle: Annotated[P[HANDLE], SAL("_Out_")],
                        DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                        ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                        Uow: Annotated[P[GUID], SAL("_In_opt_")],
                        TmHandle: Annotated[HANDLE, SAL("_In_opt_")],
                        CreateOptions: Annotated[ULONG, SAL("_In_opt_")],
                        IsolationLevel: Annotated[ULONG, SAL("_In_opt_")],
                        IsolationFlags: Annotated[ULONG, SAL("_In_opt_")],
                        Timeout: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")],
                        Description: Annotated[P[UNICODE_STRING], SAL("_In_opt_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwCreateTransactionManager(dp: Dumpulator,
                               TmHandle: Annotated[P[HANDLE], SAL("_Out_")],
                               DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                               ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                               LogFileName: Annotated[P[UNICODE_STRING], SAL("_In_opt_")],
                               CreateOptions: Annotated[ULONG, SAL("_In_opt_")],
                               CommitStrength: Annotated[ULONG, SAL("_In_opt_")]
                               ):
    raise NotImplementedError()

@syscall
def ZwCreateUserProcess(dp: Dumpulator,
                        ProcessHandle: Annotated[P[HANDLE], SAL("_Out_")],
                        ThreadHandle: Annotated[P[HANDLE], SAL("_Out_")],
                        ProcessDesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                        ThreadDesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                        ProcessObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                        ThreadObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                        ProcessFlags: Annotated[ULONG, SAL("_In_", "PROCESS_CREATE_FLAGS_*")],
                        ThreadFlags: Annotated[ULONG, SAL("_In_", "THREAD_CREATE_FLAGS_*")],
                        ProcessParameters: Annotated[PVOID, SAL("_In_opt_", "PRTL_USER_PROCESS_PARAMETERS")],
                        CreateInfo: Annotated[P[PS_CREATE_INFO], SAL("_Inout_")],
                        AttributeList: Annotated[P[PS_ATTRIBUTE_LIST], SAL("_In_opt_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwCreateWaitablePort(dp: Dumpulator,
                         PortHandle: Annotated[P[HANDLE], SAL("_Out_")],
                         ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                         MaxConnectionInfoLength: Annotated[ULONG, SAL("_In_")],
                         MaxMessageLength: Annotated[ULONG, SAL("_In_")],
                         MaxPoolUsage: Annotated[ULONG, SAL("_In_opt_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwCreateWaitCompletionPacket(dp: Dumpulator,
                                 WaitCompletionPacketHandle: Annotated[P[HANDLE], SAL("_Out_")],
                                 DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                                 ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")]
                                 ):
    raise NotImplementedError()

@syscall
def ZwCreateWnfStateName(dp: Dumpulator,
                         StateName: Annotated[P[WNF_STATE_NAME], SAL("_Out_")],
                         NameLifetime: Annotated[WNF_STATE_NAME_LIFETIME, SAL("_In_")],
                         DataScope: Annotated[WNF_DATA_SCOPE, SAL("_In_")],
                         PersistData: Annotated[BOOLEAN, SAL("_In_")],
                         TypeId: Annotated[P[CWNF_TYPE_ID], SAL("_In_opt_")],
                         MaximumStateSize: Annotated[ULONG, SAL("_In_")],
                         SecurityDescriptor: Annotated[P[SECURITY_DESCRIPTOR], SAL("_In_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwCreateWorkerFactory(dp: Dumpulator,
                          WorkerFactoryHandleReturn: Annotated[P[HANDLE], SAL("_Out_")],
                          DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                          ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                          CompletionPortHandle: Annotated[HANDLE, SAL("_In_")],
                          WorkerProcessHandle: Annotated[HANDLE, SAL("_In_")],
                          StartRoutine: Annotated[PVOID, SAL("_In_")],
                          StartParameter: Annotated[PVOID, SAL("_In_opt_")],
                          MaxThreadCount: Annotated[ULONG, SAL("_In_opt_")],
                          StackReserve: Annotated[SIZE_T, SAL("_In_opt_")],
                          StackCommit: Annotated[SIZE_T, SAL("_In_opt_")]
                          ):
    raise NotImplementedError()

@syscall
def ZwDebugActiveProcess(dp: Dumpulator,
                         ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                         DebugObjectHandle: Annotated[HANDLE, SAL("_In_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwDebugContinue(dp: Dumpulator,
                    DebugObjectHandle: Annotated[HANDLE, SAL("_In_")],
                    ClientId: Annotated[P[CLIENT_ID], SAL("_In_")],
                    ContinueStatus: Annotated[NTSTATUS, SAL("_In_")]
                    ):
    raise NotImplementedError()

@syscall
def ZwDelayExecution(dp: Dumpulator,
                     Alertable: Annotated[BOOLEAN, SAL("_In_")],
                     DelayInterval: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                     ):
    return STATUS_SUCCESS

@syscall
def ZwDeleteAtom(dp: Dumpulator,
                 Atom: Annotated[RTL_ATOM, SAL("_In_")]
                 ):
    raise NotImplementedError()

@syscall
def ZwDeleteBootEntry(dp: Dumpulator,
                      Id: Annotated[ULONG, SAL("_In_")]
                      ):
    raise NotImplementedError()

@syscall
def ZwDeleteDriverEntry(dp: Dumpulator,
                        Id: Annotated[ULONG, SAL("_In_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwDeleteFile(dp: Dumpulator,
                 ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")]
                 ):
    raise NotImplementedError()

@syscall
def ZwDeleteKey(dp: Dumpulator,
                KeyHandle: Annotated[HANDLE, SAL("_In_")]
                ):
    raise NotImplementedError()

@syscall
def ZwDeleteObjectAuditAlarm(dp: Dumpulator,
                             SubsystemName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                             HandleId: Annotated[PVOID, SAL("_In_opt_")],
                             GenerateOnClose: Annotated[BOOLEAN, SAL("_In_")]
                             ):
    raise NotImplementedError()

@syscall
def ZwDeletePrivateNamespace(dp: Dumpulator,
                             NamespaceHandle: Annotated[HANDLE, SAL("_In_")]
                             ):
    raise NotImplementedError()

@syscall
def ZwDeleteValueKey(dp: Dumpulator,
                     KeyHandle: Annotated[HANDLE, SAL("_In_")],
                     ValueName: Annotated[P[UNICODE_STRING], SAL("_In_")]
                     ):
    raise NotImplementedError()

@syscall
def ZwDeleteWnfStateData(dp: Dumpulator,
                         StateName: Annotated[P[CWNF_STATE_NAME], SAL("_In_")],
                         ExplicitScope: Annotated[PVOID, SAL("_In_opt_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwDeleteWnfStateName(dp: Dumpulator,
                         StateName: Annotated[P[CWNF_STATE_NAME], SAL("_In_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwDeviceIoControlFile(dp: Dumpulator,
                          FileHandle: Annotated[HANDLE, SAL("_In_")],
                          Event: Annotated[HANDLE, SAL("_In_opt_")],
                          ApcRoutine: Annotated[P[IO_APC_ROUTINE], SAL("_In_opt_")],
                          ApcContext: Annotated[PVOID, SAL("_In_opt_")],
                          IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                          IoControlCode: Annotated[ULONG, SAL("_In_")],
                          InputBuffer: Annotated[PVOID, SAL("_In_reads_bytes_opt_(InputBufferLength)")],
                          InputBufferLength: Annotated[ULONG, SAL("_In_")],
                          OutputBuffer: Annotated[PVOID, SAL("_Out_writes_bytes_opt_(OutputBufferLength)")],
                          OutputBufferLength: Annotated[ULONG, SAL("_In_")]
                          ):
    assert Event == 0
    assert ApcRoutine == 0
    assert ApcContext == 0
    assert OutputBufferLength == 0
    if dp.handles.valid(FileHandle):
        device = dp.handles.get(FileHandle, DeviceObject)
        in_data = bytes(dp.read(InputBuffer.ptr, InputBufferLength))
        control = DeviceControlData(dp, IoControlCode, in_data)
        out_data = device.io_control(dp, control)  # TODO: allow changing the status code
        if out_data is not None:
            written = len(out_data)
            raise NotImplementedError()
        else:
            written = 0
            assert OutputBuffer == 0

        # Construct the status block
        io_status = control.io_status
        if io_status is None:
            io_status = STATUS_SUCCESS
        io_information = control.io_information
        if io_information is None:
            io_information = written
        IO_STATUS_BLOCK.write(IoStatusBlock, io_status, io_information)
        return STATUS_SUCCESS  # TODO: figure out if the control implementation can make this fail

    raise NotImplementedError()  # TODO: INVALID_HANDLE_VALUE

@syscall
def ZwDisableLastKnownGood(dp: Dumpulator
                           ):
    raise NotImplementedError()

@syscall
def ZwDisplayString(dp: Dumpulator,
                    String: Annotated[P[UNICODE_STRING], SAL("_In_")]
                    ):
    print("debug: " + String.read_unicode_str())
    return STATUS_PRIVILEGE_NOT_HELD

@syscall
def ZwDrawText(dp: Dumpulator,
               Text: Annotated[P[UNICODE_STRING], SAL("_In_")]
               ):
    raise NotImplementedError()

@syscall
def ZwDuplicateObject(dp: Dumpulator,
                      SourceProcessHandle: Annotated[HANDLE, SAL("_In_")],
                      SourceHandle: Annotated[HANDLE, SAL("_In_")],
                      TargetProcessHandle: Annotated[HANDLE, SAL("_In_opt_")],
                      TargetHandle: Annotated[P[HANDLE], SAL("_Out_opt_")],
                      DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                      HandleAttributes: Annotated[ULONG, SAL("_In_")],
                      Options: Annotated[ULONG, SAL("_In_")]
                      ):
    assert SourceProcessHandle == dp.NtCurrentProcess()
    assert TargetProcessHandle == dp.NtCurrentProcess()
    if not dp.handles.valid(SourceHandle):
        return STATUS_INVALID_HANDLE
    dup_handle = dp.handles.duplicate(SourceHandle)
    TargetHandle.write_ptr(dup_handle)
    return STATUS_SUCCESS

@syscall
def ZwDuplicateToken(dp: Dumpulator,
                     ExistingTokenHandle: Annotated[HANDLE, SAL("_In_")],
                     DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                     ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                     EffectiveOnly: Annotated[BOOLEAN, SAL("_In_")],
                     Type: Annotated[TOKEN_TYPE, SAL("_In_")],
                     NewTokenHandle: Annotated[P[HANDLE], SAL("_Out_")]
                     ):
    raise NotImplementedError()

@syscall
def ZwEnableLastKnownGood(dp: Dumpulator
                          ):
    raise NotImplementedError()

@syscall
def ZwEnumerateBootEntries(dp: Dumpulator,
                           Buffer: Annotated[PVOID, SAL("_Out_writes_bytes_opt_(*BufferLength)")],
                           BufferLength: Annotated[P[ULONG], SAL("_Inout_")]
                           ):
    raise NotImplementedError()

@syscall
def ZwEnumerateDriverEntries(dp: Dumpulator,
                             Buffer: Annotated[PVOID, SAL("_Out_writes_bytes_opt_(*BufferLength)")],
                             BufferLength: Annotated[P[ULONG], SAL("_Inout_")]
                             ):
    raise NotImplementedError()

@syscall
def ZwEnumerateKey(dp: Dumpulator,
                   KeyHandle: Annotated[HANDLE, SAL("_In_")],
                   Index: Annotated[ULONG, SAL("_In_")],
                   KeyInformationClass: Annotated[KEY_INFORMATION_CLASS, SAL("_In_")],
                   KeyInformation: Annotated[PVOID, SAL("_Out_writes_bytes_opt_(Length)")],
                   Length: Annotated[ULONG, SAL("_In_")],
                   ResultLength: Annotated[P[ULONG], SAL("_Out_")]
                   ):
    raise NotImplementedError()

@syscall
def ZwEnumerateSystemEnvironmentValuesEx(dp: Dumpulator,
                                         InformationClass: Annotated[ULONG, SAL("_In_", "SYSTEM_ENVIRONMENT_INFORMATION_CLASS")],
                                         Buffer: Annotated[PVOID, SAL("_Out_")],
                                         BufferLength: Annotated[P[ULONG], SAL("_Inout_")]
                                         ):
    raise NotImplementedError()

@syscall
def ZwEnumerateTransactionObject(dp: Dumpulator,
                                 RootObjectHandle: Annotated[HANDLE, SAL("_In_opt_")],
                                 QueryType: Annotated[KTMOBJECT_TYPE, SAL("_In_")],
                                 ObjectCursor: Annotated[P[KTMOBJECT_CURSOR], SAL("_Inout_updates_bytes_(ObjectCursorLength)")],
                                 ObjectCursorLength: Annotated[ULONG, SAL("_In_")],
                                 ReturnLength: Annotated[P[ULONG], SAL("_Out_")]
                                 ):
    raise NotImplementedError()

@syscall
def ZwEnumerateValueKey(dp: Dumpulator,
                        KeyHandle: Annotated[HANDLE, SAL("_In_")],
                        Index: Annotated[ULONG, SAL("_In_")],
                        KeyValueInformationClass: Annotated[KEY_VALUE_INFORMATION_CLASS, SAL("_In_")],
                        KeyValueInformation: Annotated[PVOID, SAL("_Out_writes_bytes_opt_(Length)")],
                        Length: Annotated[ULONG, SAL("_In_")],
                        ResultLength: Annotated[P[ULONG], SAL("_Out_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwExtendSection(dp: Dumpulator,
                    SectionHandle: Annotated[HANDLE, SAL("_In_")],
                    NewSectionSize: Annotated[P[LARGE_INTEGER], SAL("_Inout_")]
                    ):
    raise NotImplementedError()

@syscall
def ZwFilterBootOption(dp: Dumpulator,
                       FilterOperation: Annotated[FILTER_BOOT_OPTION_OPERATION, SAL("_In_")],
                       ObjectType: Annotated[ULONG, SAL("_In_")],
                       ElementType: Annotated[ULONG, SAL("_In_")],
                       Data: Annotated[PVOID, SAL("_In_reads_bytes_opt_(DataSize)")],
                       DataSize: Annotated[ULONG, SAL("_In_")]
                       ):
    raise NotImplementedError()

@syscall
def ZwFilterToken(dp: Dumpulator,
                  ExistingTokenHandle: Annotated[HANDLE, SAL("_In_")],
                  Flags: Annotated[ULONG, SAL("_In_")],
                  SidsToDisable: Annotated[P[TOKEN_GROUPS], SAL("_In_opt_")],
                  PrivilegesToDelete: Annotated[P[TOKEN_PRIVILEGES], SAL("_In_opt_")],
                  RestrictedSids: Annotated[P[TOKEN_GROUPS], SAL("_In_opt_")],
                  NewTokenHandle: Annotated[P[HANDLE], SAL("_Out_")]
                  ):
    raise NotImplementedError()

@syscall
def ZwFilterTokenEx(dp: Dumpulator,
                    ExistingTokenHandle: Annotated[HANDLE, SAL("_In_")],
                    Flags: Annotated[ULONG, SAL("_In_")],
                    SidsToDisable: Annotated[P[TOKEN_GROUPS], SAL("_In_opt_")],
                    PrivilegesToDelete: Annotated[P[TOKEN_PRIVILEGES], SAL("_In_opt_")],
                    RestrictedSids: Annotated[P[TOKEN_GROUPS], SAL("_In_opt_")],
                    DisableUserClaimsCount: Annotated[ULONG, SAL("_In_")],
                    UserClaimsToDisable: Annotated[P[UNICODE_STRING], SAL("_In_opt_")],
                    DisableDeviceClaimsCount: Annotated[ULONG, SAL("_In_")],
                    DeviceClaimsToDisable: Annotated[P[UNICODE_STRING], SAL("_In_opt_")],
                    DeviceGroupsToDisable: Annotated[P[TOKEN_GROUPS], SAL("_In_opt_")],
                    RestrictedUserAttributes: Annotated[P[TOKEN_SECURITY_ATTRIBUTES_INFORMATION], SAL("_In_opt_")],
                    RestrictedDeviceAttributes: Annotated[P[TOKEN_SECURITY_ATTRIBUTES_INFORMATION], SAL("_In_opt_")],
                    RestrictedDeviceGroups: Annotated[P[TOKEN_GROUPS], SAL("_In_opt_")],
                    NewTokenHandle: Annotated[P[HANDLE], SAL("_Out_")]
                    ):
    raise NotImplementedError()

@syscall
def ZwFindAtom(dp: Dumpulator,
               AtomName: Annotated[PWSTR, SAL("_In_reads_bytes_opt_(Length)")],
               Length: Annotated[ULONG, SAL("_In_")],
               Atom: Annotated[P[RTL_ATOM], SAL("_Out_opt_")]
               ):
    raise NotImplementedError()

@syscall
def ZwFlushBuffersFile(dp: Dumpulator,
                       FileHandle: Annotated[HANDLE, SAL("_In_")],
                       IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")]
                       ):
    raise NotImplementedError()

@syscall
def ZwFlushBuffersFileEx(dp: Dumpulator,
                         FileHandle: Annotated[HANDLE, SAL("_In_")],
                         Flags: Annotated[ULONG, SAL("_In_")],
                         Parameters: Annotated[PVOID, SAL("_In_reads_bytes_(ParametersSize)")],
                         ParametersSize: Annotated[ULONG, SAL("_In_")],
                         IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwFlushInstallUILanguage(dp: Dumpulator,
                             InstallUILanguage: Annotated[LANGID, SAL("_In_")],
                             SetComittedFlag: Annotated[ULONG, SAL("_In_")]
                             ):
    raise NotImplementedError()

@syscall
def ZwFlushInstructionCache(dp: Dumpulator,
                            ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                            BaseAddress: Annotated[PVOID, SAL("_In_opt_")],
                            Length: Annotated[SIZE_T, SAL("_In_")]
                            ):
    raise NotImplementedError()

@syscall
def ZwFlushKey(dp: Dumpulator,
               KeyHandle: Annotated[HANDLE, SAL("_In_")]
               ):
    raise NotImplementedError()

@syscall
def ZwFlushProcessWriteBuffers(dp: Dumpulator
                               ):
    raise NotImplementedError()

@syscall
def ZwFlushVirtualMemory(dp: Dumpulator,
                         ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                         BaseAddress: Annotated[P[PVOID], SAL("_Inout_")],
                         RegionSize: Annotated[P[SIZE_T], SAL("_Inout_")],
                         IoStatus: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwFlushWriteBuffer(dp: Dumpulator
                       ):
    raise NotImplementedError()

@syscall
def ZwFreeUserPhysicalPages(dp: Dumpulator,
                            ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                            NumberOfPages: Annotated[P[ULONG_PTR], SAL("_Inout_")],
                            UserPfnArray: Annotated[P[ULONG_PTR], SAL("_In_reads_(*NumberOfPages)")]
                            ):
    raise NotImplementedError()

@syscall
def ZwFreeVirtualMemory(dp: Dumpulator,
                        ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                        BaseAddress: Annotated[P[PVOID], SAL("_Inout_")],
                        RegionSize: Annotated[P[SIZE_T], SAL("_Inout_")],
                        FreeType: Annotated[ULONG, SAL("_In_")]
                        ):
    base = BaseAddress.read_ptr()
    size = RegionSize.read_ptr()
    if FreeType == MEM_RELEASE:
        print(f"release {hex(base)}[{hex(size)}]")
        assert size == 0
        region = dp.memory.find_region(base)
        if region is None:
            return STATUS_MEMORY_NOT_ALLOCATED
        dp.memory.release(base)
        return STATUS_SUCCESS
    elif FreeType == MEM_DECOMMIT:
        print(f"decommit {hex(base)}[{hex(size)}]")
        region = dp.memory.find_region(base)
        if region is None:
            return STATUS_MEMORY_NOT_ALLOCATED
        dp.memory.decommit(base, size)
        return STATUS_SUCCESS
    else:
        raise NotImplementedError()

@syscall
def ZwFreezeRegistry(dp: Dumpulator,
                     TimeOutInSeconds: Annotated[ULONG, SAL("_In_")]
                     ):
    raise NotImplementedError()

@syscall
def ZwFreezeTransactions(dp: Dumpulator,
                         FreezeTimeout: Annotated[P[LARGE_INTEGER], SAL("_In_")],
                         ThawTimeout: Annotated[P[LARGE_INTEGER], SAL("_In_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwFsControlFile(dp: Dumpulator,
                    FileHandle: Annotated[HANDLE, SAL("_In_")],
                    Event: Annotated[HANDLE, SAL("_In_opt_")],
                    ApcRoutine: Annotated[P[IO_APC_ROUTINE], SAL("_In_opt_")],
                    ApcContext: Annotated[PVOID, SAL("_In_opt_")],
                    IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                    FsControlCode: Annotated[ULONG, SAL("_In_")],
                    InputBuffer: Annotated[PVOID, SAL("_In_reads_bytes_opt_(InputBufferLength)")],
                    InputBufferLength: Annotated[ULONG, SAL("_In_")],
                    OutputBuffer: Annotated[PVOID, SAL("_Out_writes_bytes_opt_(OutputBufferLength)")],
                    OutputBufferLength: Annotated[ULONG, SAL("_In_")]
                    ):
    raise NotImplementedError()

@syscall
def ZwGetCachedSigningLevel(dp: Dumpulator,
                            File: Annotated[HANDLE, SAL("_In_")],
                            Flags: Annotated[P[ULONG], SAL("_Out_")],
                            SigningLevel: Annotated[P[SE_SIGNING_LEVEL], SAL("_Out_")],
                            Thumbprint: Annotated[P[UCHAR], SAL("_Out_writes_bytes_to_opt_(*ThumbprintSize, *ThumbprintSize)")],
                            ThumbprintSize: Annotated[P[ULONG], SAL("_Inout_opt_")],
                            ThumbprintAlgorithm: Annotated[P[ULONG], SAL("_Out_opt_")]
                            ):
    raise NotImplementedError()

@syscall
def ZwGetCompleteWnfStateSubscription(dp: Dumpulator,
                                      OldDescriptorStateName: Annotated[P[WNF_STATE_NAME], SAL("_In_opt_")],
                                      OldSubscriptionId: Annotated[P[ULONG64], SAL("_In_opt_")],
                                      OldDescriptorEventMask: Annotated[ULONG, SAL("_In_opt_")],
                                      OldDescriptorStatus: Annotated[ULONG, SAL("_In_opt_")],
                                      NewDeliveryDescriptor: Annotated[P[WNF_DELIVERY_DESCRIPTOR], SAL("_Out_writes_bytes_(DescriptorSize)")],
                                      DescriptorSize: Annotated[ULONG, SAL("_In_")]
                                      ):
    raise NotImplementedError()

@syscall
def ZwGetContextThread(dp: Dumpulator,
                       ThreadHandle: Annotated[HANDLE, SAL("_In_")],
                       ThreadContext: Annotated[P[CONTEXT], SAL("_Inout_")]
                       ):
    raise NotImplementedError()

@syscall
def ZwGetCurrentProcessorNumber(dp: Dumpulator
                                ):
    raise NotImplementedError()

@syscall
def ZwGetCurrentProcessorNumberEx(dp: Dumpulator,
                                  ProcessorNumber: Annotated[P[PROCESSOR_NUMBER], SAL("_Out_opt_")]
                                  ):
    raise NotImplementedError()

@syscall
def ZwGetDevicePowerState(dp: Dumpulator,
                          Device: Annotated[HANDLE, SAL("_In_")],
                          State: Annotated[P[DEVICE_POWER_STATE], SAL("_Out_")]
                          ):
    raise NotImplementedError()

@syscall
def ZwGetMUIRegistryInfo(dp: Dumpulator,
                         Flags: Annotated[ULONG, SAL("_In_")],
                         DataSize: Annotated[P[ULONG], SAL("_Inout_")],
                         Data: Annotated[PVOID, SAL("_Out_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwGetNextProcess(dp: Dumpulator,
                     ProcessHandle: Annotated[HANDLE, SAL("_In_opt_")],
                     DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                     HandleAttributes: Annotated[ULONG, SAL("_In_")],
                     Flags: Annotated[ULONG, SAL("_In_")],
                     NewProcessHandle: Annotated[P[HANDLE], SAL("_Out_")]
                     ):
    raise NotImplementedError()

@syscall
def ZwGetNextThread(dp: Dumpulator,
                    ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                    ThreadHandle: Annotated[HANDLE, SAL("_In_opt_")],
                    DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                    HandleAttributes: Annotated[ULONG, SAL("_In_")],
                    Flags: Annotated[ULONG, SAL("_In_")],
                    NewThreadHandle: Annotated[P[HANDLE], SAL("_Out_")]
                    ):
    raise NotImplementedError()

@syscall
def ZwGetNlsSectionPtr(dp: Dumpulator,
                       SectionType: Annotated[ULONG, SAL("_In_")],
                       SectionData: Annotated[ULONG, SAL("_In_")],
                       ContextData: Annotated[PVOID, SAL("_In_")],
                       SectionPointer: Annotated[P[PVOID], SAL("_Out_")],
                       SectionSize: Annotated[P[ULONG], SAL("_Out_")]
                       ):
    raise NotImplementedError()

@syscall
def ZwGetNotificationResourceManager(dp: Dumpulator,
                                     ResourceManagerHandle: Annotated[HANDLE, SAL("_In_")],
                                     TransactionNotification: Annotated[P[TRANSACTION_NOTIFICATION], SAL("_Out_")],
                                     NotificationLength: Annotated[ULONG, SAL("_In_")],
                                     Timeout: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")],
                                     ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")],
                                     Asynchronous: Annotated[ULONG, SAL("_In_")],
                                     AsynchronousContext: Annotated[ULONG_PTR, SAL("_In_opt_")]
                                     ):
    raise NotImplementedError()

@syscall
def ZwGetPlugPlayEvent(dp: Dumpulator,
                       EventHandle: Annotated[HANDLE, SAL("_In_")],
                       Context: Annotated[PVOID, SAL("_In_opt_")],
                       EventBlock: Annotated[P[PLUGPLAY_EVENT_BLOCK], SAL("_Out_writes_bytes_(EventBufferSize)")],
                       EventBufferSize: Annotated[ULONG, SAL("_In_")]
                       ):
    raise NotImplementedError()

@syscall
def ZwGetWriteWatch(dp: Dumpulator,
                    ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                    Flags: Annotated[ULONG, SAL("_In_")],
                    BaseAddress: Annotated[PVOID, SAL("_In_")],
                    RegionSize: Annotated[SIZE_T, SAL("_In_")],
                    UserAddressArray: Annotated[P[PVOID], SAL("_Out_writes_(*EntriesInUserAddressArray)")],
                    EntriesInUserAddressArray: Annotated[P[ULONG_PTR], SAL("_Inout_")],
                    Granularity: Annotated[P[ULONG], SAL("_Out_")]
                    ):
    raise NotImplementedError()

@syscall
def ZwImpersonateAnonymousToken(dp: Dumpulator,
                                ThreadHandle: Annotated[HANDLE, SAL("_In_")]
                                ):
    raise NotImplementedError()

@syscall
def ZwImpersonateClientOfPort(dp: Dumpulator,
                              PortHandle: Annotated[HANDLE, SAL("_In_")],
                              Message: Annotated[P[PORT_MESSAGE], SAL("_In_")]
                              ):
    raise NotImplementedError()

@syscall
def ZwImpersonateThread(dp: Dumpulator,
                        ServerThreadHandle: Annotated[HANDLE, SAL("_In_")],
                        ClientThreadHandle: Annotated[HANDLE, SAL("_In_")],
                        SecurityQos: Annotated[P[SECURITY_QUALITY_OF_SERVICE], SAL("_In_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwInitializeEnclave(dp: Dumpulator,
                        ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                        BaseAddress: Annotated[PVOID, SAL("_In_")],
                        EnclaveInformation: Annotated[PVOID, SAL("_In_reads_bytes_(EnclaveInformationLength)")],
                        EnclaveInformationLength: Annotated[ULONG, SAL("_In_")],
                        EnclaveError: Annotated[P[ULONG], SAL("_Out_opt_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwInitializeNlsFiles(dp: Dumpulator,
                         BaseAddress: Annotated[P[PVOID], SAL("_Out_")],
                         DefaultLocaleId: Annotated[P[LCID], SAL("_Out_")],
                         DefaultCasingTableSize: Annotated[P[LARGE_INTEGER], SAL("_Out_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwInitializeRegistry(dp: Dumpulator,
                         BootCondition: Annotated[USHORT, SAL("_In_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwInitiatePowerAction(dp: Dumpulator,
                          SystemAction: Annotated[P[OWER_ACTION], SAL("_In_")],
                          LightestSystemState: Annotated[SYSTEM_POWER_STATE, SAL("_In_")],
                          Flags: Annotated[ULONG, SAL("_In_", "POWER_ACTION_* flags")],
                          Asynchronous: Annotated[BOOLEAN, SAL("_In_")]
                          ):
    raise NotImplementedError()

@syscall
def ZwIsProcessInJob(dp: Dumpulator,
                     ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                     JobHandle: Annotated[HANDLE, SAL("_In_opt_")]
                     ):
    raise NotImplementedError()

@syscall
def ZwIsSystemResumeAutomatic(dp: Dumpulator
                              ):
    raise NotImplementedError()

@syscall
def ZwIsUILanguageComitted(dp: Dumpulator
                           ):
    raise NotImplementedError()

@syscall
def ZwListenPort(dp: Dumpulator,
                 PortHandle: Annotated[HANDLE, SAL("_In_")],
                 ConnectionRequest: Annotated[P[PORT_MESSAGE], SAL("_Out_")]
                 ):
    raise NotImplementedError()

@syscall
def ZwLoadDriver(dp: Dumpulator,
                 DriverServiceName: Annotated[P[UNICODE_STRING], SAL("_In_")]
                 ):
    print(f"Starting service: {DriverServiceName[0].read_str()}")
    return STATUS_SUCCESS

@syscall
def ZwLoadEnclaveData(dp: Dumpulator,
                      ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                      BaseAddress: Annotated[PVOID, SAL("_In_")],
                      Buffer: Annotated[PVOID, SAL("_In_reads_bytes_(BufferSize)")],
                      BufferSize: Annotated[SIZE_T, SAL("_In_")],
                      Protect: Annotated[ULONG, SAL("_In_")],
                      PageInformation: Annotated[PVOID, SAL("_In_reads_bytes_(PageInformationLength)")],
                      PageInformationLength: Annotated[ULONG, SAL("_In_")],
                      NumberOfBytesWritten: Annotated[P[SIZE_T], SAL("_Out_opt_")],
                      EnclaveError: Annotated[P[ULONG], SAL("_Out_opt_")]
                      ):
    raise NotImplementedError()

@syscall
def ZwLoadKey(dp: Dumpulator,
              TargetKey: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
              SourceFile: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")]
              ):
    raise NotImplementedError()

@syscall
def ZwLoadKey2(dp: Dumpulator,
               TargetKey: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
               SourceFile: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
               Flags: Annotated[ULONG, SAL("_In_")]
               ):
    raise NotImplementedError()

@syscall
def ZwLoadKey3(dp: Dumpulator,
               TargetKey: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
               SourceFile: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
               Flags: Annotated[ULONG, SAL("_In_")],
               LoadEntries: Annotated[P[KEY_LOAD_ENTRY], SAL("_In_reads_(LoadEntryCount)")],
               LoadEntryCount: Annotated[ULONG, SAL("_In_")],
               DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_opt_")],
               RootHandle: Annotated[P[HANDLE], SAL("_Out_opt_")],
               Reserved: Annotated[PVOID, SAL("_Reserved_")]
               ):
    raise NotImplementedError()

@syscall
def ZwLoadKeyEx(dp: Dumpulator,
                TargetKey: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
                SourceFile: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
                Flags: Annotated[ULONG, SAL("_In_")],
                TrustClassKey: Annotated[HANDLE, SAL("_In_opt_", "this and below were added on Win10")],
                Event: Annotated[HANDLE, SAL("_In_opt_")],
                DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_opt_")],
                RootHandle: Annotated[P[HANDLE], SAL("_Out_opt_")],
                Reserved: Annotated[PVOID, SAL("_Reserved_", "previously PIO_STATUS_BLOCK")]
                ):
    raise NotImplementedError()

@syscall
def ZwLockFile(dp: Dumpulator,
               FileHandle: Annotated[HANDLE, SAL("_In_")],
               Event: Annotated[HANDLE, SAL("_In_opt_")],
               ApcRoutine: Annotated[P[IO_APC_ROUTINE], SAL("_In_opt_")],
               ApcContext: Annotated[PVOID, SAL("_In_opt_")],
               IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
               ByteOffset: Annotated[P[LARGE_INTEGER], SAL("_In_")],
               Length: Annotated[P[LARGE_INTEGER], SAL("_In_")],
               Key: Annotated[ULONG, SAL("_In_")],
               FailImmediately: Annotated[BOOLEAN, SAL("_In_")],
               ExclusiveLock: Annotated[BOOLEAN, SAL("_In_")]
               ):
    raise NotImplementedError()

@syscall
def ZwLockProductActivationKeys(dp: Dumpulator,
                                pPrivateVer: Annotated[P[ULONG], SAL("_Inout_opt_")],
                                pSafeMode: Annotated[P[ULONG], SAL("_Out_opt_")]
                                ):
    raise NotImplementedError()

@syscall
def ZwLockRegistryKey(dp: Dumpulator,
                      KeyHandle: Annotated[HANDLE, SAL("_In_")]
                      ):
    raise NotImplementedError()

@syscall
def ZwLockVirtualMemory(dp: Dumpulator,
                        ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                        BaseAddress: Annotated[P[PVOID], SAL("_Inout_")],
                        RegionSize: Annotated[P[SIZE_T], SAL("_Inout_")],
                        MapType: Annotated[ULONG, SAL("_In_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwMakePermanentObject(dp: Dumpulator,
                          Handle: Annotated[HANDLE, SAL("_In_")]
                          ):
    raise NotImplementedError()

@syscall
def ZwMakeTemporaryObject(dp: Dumpulator,
                          Handle: Annotated[HANDLE, SAL("_In_")]
                          ):
    raise NotImplementedError()

@syscall
def ZwManagePartition(dp: Dumpulator,
                      TargetHandle: Annotated[HANDLE, SAL("_In_")],
                      SourceHandle: Annotated[HANDLE, SAL("_In_opt_")],
                      PartitionInformationClass: Annotated[PARTITION_INFORMATION_CLASS, SAL("_In_")],
                      PartitionInformation: Annotated[PVOID, SAL("_Inout_updates_bytes_(PartitionInformationLength)")],
                      PartitionInformationLength: Annotated[ULONG, SAL("_In_")]
                      ):
    raise NotImplementedError()

@syscall
def ZwMapCMFModule(dp: Dumpulator,
                   What: Annotated[ULONG, SAL("_In_")],
                   Index: Annotated[ULONG, SAL("_In_")],
                   CacheIndexOut: Annotated[P[ULONG], SAL("_Out_opt_")],
                   CacheFlagsOut: Annotated[P[ULONG], SAL("_Out_opt_")],
                   ViewSizeOut: Annotated[P[ULONG], SAL("_Out_opt_")],
                   BaseAddress: Annotated[P[PVOID], SAL("_Out_opt_")]
                   ):
    raise NotImplementedError()

@syscall
def ZwMapUserPhysicalPages(dp: Dumpulator,
                           VirtualAddress: Annotated[PVOID, SAL("_In_")],
                           NumberOfPages: Annotated[ULONG_PTR, SAL("_In_")],
                           UserPfnArray: Annotated[P[ULONG_PTR], SAL("_In_reads_opt_(NumberOfPages)")]
                           ):
    raise NotImplementedError()

@syscall
def ZwMapUserPhysicalPagesScatter(dp: Dumpulator,
                                  VirtualAddresses: Annotated[P[PVOID], SAL("_In_reads_(NumberOfPages)")],
                                  NumberOfPages: Annotated[ULONG_PTR, SAL("_In_")],
                                  UserPfnArray: Annotated[P[ULONG_PTR], SAL("_In_reads_opt_(NumberOfPages)")]
                                  ):
    raise NotImplementedError()

@syscall
def ZwMapViewOfSection(dp: Dumpulator,
                       SectionHandle: Annotated[HANDLE, SAL("_In_")],
                       ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                       BaseAddress: Annotated[P[PVOID], SAL("_Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize))")],
                       ZeroBits: Annotated[ULONG_PTR, SAL("_In_")],
                       CommitSize: Annotated[SIZE_T, SAL("_In_")],
                       SectionOffset: Annotated[P[LARGE_INTEGER], SAL("_Inout_opt_")],
                       ViewSize: Annotated[P[SIZE_T], SAL("_Inout_")],
                       InheritDisposition: Annotated[SECTION_INHERIT, SAL("_In_")],
                       AllocationType: Annotated[ULONG, SAL("_In_")],
                       Win32Protect: Annotated[ULONG, SAL("_In_")]
                       ):
    assert ProcessHandle == dp.NtCurrentProcess()
    assert ZeroBits == 0
    assert CommitSize == 0
    assert SectionOffset == 0
    assert InheritDisposition == SECTION_INHERIT.ViewShare
    assert AllocationType == MEM_DIFFERENT_IMAGE_BASE_OK
    assert Win32Protect == PAGE_EXECUTE_WRITECOPY
    requested_base = BaseAddress.read_ptr()
    assert requested_base == 0
    section = dp.handles.get(SectionHandle, SectionObject)
    data = section.file.read()
    module = dp.map_module(data, section.file.path, requested_base, False)

    # Handle out parameters
    BaseAddress.write_ptr(module.base)
    ViewSize.write_ptr(module.size)
    return STATUS_SUCCESS

@syscall
def ZwModifyBootEntry(dp: Dumpulator,
                      BootEntry: Annotated[P[BOOT_ENTRY], SAL("_In_")]
                      ):
    raise NotImplementedError()

@syscall
def ZwModifyDriverEntry(dp: Dumpulator,
                        DriverEntry: Annotated[P[EFI_DRIVER_ENTRY], SAL("_In_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwNotifyChangeDirectoryFile(dp: Dumpulator,
                                FileHandle: Annotated[HANDLE, SAL("_In_")],
                                Event: Annotated[HANDLE, SAL("_In_opt_")],
                                ApcRoutine: Annotated[P[IO_APC_ROUTINE], SAL("_In_opt_")],
                                ApcContext: Annotated[PVOID, SAL("_In_opt_")],
                                IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                                Buffer: Annotated[PVOID, SAL("_Out_writes_bytes_(Length)", "FILE_NOTIFY_INFORMATION")],
                                Length: Annotated[ULONG, SAL("_In_")],
                                CompletionFilter: Annotated[ULONG, SAL("_In_")],
                                WatchTree: Annotated[BOOLEAN, SAL("_In_")]
                                ):
    raise NotImplementedError()

@syscall
def ZwNotifyChangeDirectoryFileEx(dp: Dumpulator,
                                  FileHandle: Annotated[HANDLE, SAL("_In_")],
                                  Event: Annotated[HANDLE, SAL("_In_opt_")],
                                  ApcRoutine: Annotated[P[IO_APC_ROUTINE], SAL("_In_opt_")],
                                  ApcContext: Annotated[PVOID, SAL("_In_opt_")],
                                  IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                                  Buffer: Annotated[PVOID, SAL("_Out_writes_bytes_(Length)")],
                                  Length: Annotated[ULONG, SAL("_In_")],
                                  CompletionFilter: Annotated[ULONG, SAL("_In_")],
                                  WatchTree: Annotated[BOOLEAN, SAL("_In_")],
                                  DirectoryNotifyInformationClass: Annotated[DIRECTORY_NOTIFY_INFORMATION_CLASS, SAL("_In_opt_")]
                                  ):
    raise NotImplementedError()

@syscall
def ZwNotifyChangeKey(dp: Dumpulator,
                      KeyHandle: Annotated[HANDLE, SAL("_In_")],
                      Event: Annotated[HANDLE, SAL("_In_opt_")],
                      ApcRoutine: Annotated[P[IO_APC_ROUTINE], SAL("_In_opt_")],
                      ApcContext: Annotated[PVOID, SAL("_In_opt_")],
                      IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                      CompletionFilter: Annotated[ULONG, SAL("_In_")],
                      WatchTree: Annotated[BOOLEAN, SAL("_In_")],
                      Buffer: Annotated[PVOID, SAL("_Out_writes_bytes_opt_(BufferSize)")],
                      BufferSize: Annotated[ULONG, SAL("_In_")],
                      Asynchronous: Annotated[BOOLEAN, SAL("_In_")]
                      ):
    raise NotImplementedError()

@syscall
def ZwNotifyChangeMultipleKeys(dp: Dumpulator,
                               MasterKeyHandle: Annotated[HANDLE, SAL("_In_")],
                               Count: Annotated[ULONG, SAL("_In_opt_")],
                               SubordinateObjects: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_reads_opt_(Count)")],
                               Event: Annotated[HANDLE, SAL("_In_opt_")],
                               ApcRoutine: Annotated[P[IO_APC_ROUTINE], SAL("_In_opt_")],
                               ApcContext: Annotated[PVOID, SAL("_In_opt_")],
                               IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                               CompletionFilter: Annotated[ULONG, SAL("_In_")],
                               WatchTree: Annotated[BOOLEAN, SAL("_In_")],
                               Buffer: Annotated[PVOID, SAL("_Out_writes_bytes_opt_(BufferSize)")],
                               BufferSize: Annotated[ULONG, SAL("_In_")],
                               Asynchronous: Annotated[BOOLEAN, SAL("_In_")]
                               ):
    raise NotImplementedError()

@syscall
def ZwNotifyChangeSession(dp: Dumpulator,
                          SessionHandle: Annotated[HANDLE, SAL("_In_")],
                          ChangeSequenceNumber: Annotated[ULONG, SAL("_In_")],
                          ChangeTimeStamp: Annotated[P[LARGE_INTEGER], SAL("_In_")],
                          Event: Annotated[IO_SESSION_EVENT, SAL("_In_")],
                          NewState: Annotated[IO_SESSION_STATE, SAL("_In_")],
                          PreviousState: Annotated[IO_SESSION_STATE, SAL("_In_")],
                          Payload: Annotated[PVOID, SAL("_In_reads_bytes_opt_(PayloadSize)")],
                          PayloadSize: Annotated[ULONG, SAL("_In_")]
                          ):
    raise NotImplementedError()

@syscall
def ZwOpenDirectoryObject(dp: Dumpulator,
                          DirectoryHandle: Annotated[P[HANDLE], SAL("_Out_")],
                          DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                          ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")]
                          ):
    raise NotImplementedError()

@syscall
def ZwOpenEnlistment(dp: Dumpulator,
                     EnlistmentHandle: Annotated[P[HANDLE], SAL("_Out_")],
                     DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                     ResourceManagerHandle: Annotated[HANDLE, SAL("_In_")],
                     EnlistmentGuid: Annotated[P[GUID], SAL("_In_")],
                     ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")]
                     ):
    raise NotImplementedError()

@syscall
def ZwOpenEvent(dp: Dumpulator,
                EventHandle: Annotated[P[HANDLE], SAL("_Out_")],
                DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")]
                ):
    raise NotImplementedError()

@syscall
def ZwOpenEventPair(dp: Dumpulator,
                    EventPairHandle: Annotated[P[HANDLE], SAL("_Out_")],
                    DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                    ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")]
                    ):
    raise NotImplementedError()

@syscall
def ZwOpenFile(dp: Dumpulator,
               FileHandle: Annotated[P[HANDLE], SAL("_Out_")],
               DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
               ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
               IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
               ShareAccess: Annotated[ULONG, SAL("_In_")],
               OpenOptions: Annotated[ULONG, SAL("_In_")]
               ):
    assert FileHandle.ptr != 0
    assert ObjectAttributes.ptr != 0
    file_name = ObjectAttributes[0].ObjectName[0].read_str()
    handle = dp.handles.open_file(file_name)
    assert handle is not None
    FileHandle.write_ptr(handle)
    IO_STATUS_BLOCK.write(IoStatusBlock, STATUS_SUCCESS, FILE_OPENED)
    return STATUS_SUCCESS

@syscall
def ZwOpenIoCompletion(dp: Dumpulator,
                       IoCompletionHandle: Annotated[P[HANDLE], SAL("_Out_")],
                       DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                       ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")]
                       ):
    raise NotImplementedError()

@syscall
def ZwOpenJobObject(dp: Dumpulator,
                    JobHandle: Annotated[P[HANDLE], SAL("_Out_")],
                    DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                    ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")]
                    ):
    raise NotImplementedError()

@syscall
def ZwOpenKey(dp: Dumpulator,
              KeyHandle: Annotated[P[HANDLE], SAL("_Out_")],
              DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
              ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")]
              ):
    key_name = ObjectAttributes[0].ObjectName[0].read_str()
    assert DesiredAccess == 0x20019
    handle = dp.handles.open_file(key_name)
    assert handle is not None
    KeyHandle.write_ptr(handle)
    return STATUS_SUCCESS

@syscall
def ZwOpenKeyedEvent(dp: Dumpulator,
                     KeyedEventHandle: Annotated[P[HANDLE], SAL("_Out_")],
                     DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                     ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")]
                     ):
    raise NotImplementedError()

@syscall
def ZwOpenKeyEx(dp: Dumpulator,
                KeyHandle: Annotated[P[HANDLE], SAL("_Out_")],
                DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
                OpenOptions: Annotated[ULONG, SAL("_In_")]
                ):
    raise NotImplementedError()

@syscall
def ZwOpenKeyTransacted(dp: Dumpulator,
                        KeyHandle: Annotated[P[HANDLE], SAL("_Out_")],
                        DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                        ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
                        TransactionHandle: Annotated[HANDLE, SAL("_In_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwOpenKeyTransactedEx(dp: Dumpulator,
                          KeyHandle: Annotated[P[HANDLE], SAL("_Out_")],
                          DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                          ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
                          OpenOptions: Annotated[ULONG, SAL("_In_")],
                          TransactionHandle: Annotated[HANDLE, SAL("_In_")]
                          ):
    raise NotImplementedError()

@syscall
def ZwOpenMutant(dp: Dumpulator,
                 MutantHandle: Annotated[P[HANDLE], SAL("_Out_")],
                 DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                 ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")]
                 ):
    raise NotImplementedError()

@syscall
def ZwOpenObjectAuditAlarm(dp: Dumpulator,
                           SubsystemName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                           HandleId: Annotated[PVOID, SAL("_In_opt_")],
                           ObjectTypeName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                           ObjectName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                           SecurityDescriptor: Annotated[P[SECURITY_DESCRIPTOR], SAL("_In_opt_")],
                           ClientToken: Annotated[HANDLE, SAL("_In_")],
                           DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                           GrantedAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                           Privileges: Annotated[P[PRIVILEGE_SET], SAL("_In_opt_")],
                           ObjectCreation: Annotated[BOOLEAN, SAL("_In_")],
                           AccessGranted: Annotated[BOOLEAN, SAL("_In_")],
                           GenerateOnClose: Annotated[P[BOOLEAN], SAL("_Out_")]
                           ):
    raise NotImplementedError()

@syscall
def ZwOpenPartition(dp: Dumpulator,
                    PartitionHandle: Annotated[P[HANDLE], SAL("_Out_")],
                    DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                    ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")]
                    ):
    raise NotImplementedError()

@syscall
def ZwOpenPrivateNamespace(dp: Dumpulator,
                           NamespaceHandle: Annotated[P[HANDLE], SAL("_Out_")],
                           DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                           ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                           BoundaryDescriptor: Annotated[P[OBJECT_BOUNDARY_DESCRIPTOR], SAL("_In_")]
                           ):
    raise NotImplementedError()

@syscall
def ZwOpenProcess(dp: Dumpulator,
                  ProcessHandle: Annotated[P[HANDLE], SAL("_Out_")],
                  DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                  ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
                  ClientId: Annotated[P[CLIENT_ID], SAL("_In_opt_")]
                  ):
    raise NotImplementedError()

@syscall
def ZwOpenProcessToken(dp: Dumpulator,
                       ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                       DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                       TokenHandle: Annotated[P[HANDLE], SAL("_Out_")]
                       ):
    assert ProcessHandle == dp.NtCurrentProcess()
    assert DesiredAccess == 0x20
    # TODO: TokenHandle should be -6 or something
    handle = dp.handles.new(ProcessTokenObject(ProcessHandle))
    print(f"process token: {hex(handle)}")
    TokenHandle.write_ptr(handle)
    return STATUS_SUCCESS

@syscall
def ZwOpenProcessTokenEx(dp: Dumpulator,
                         ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                         DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                         HandleAttributes: Annotated[ULONG, SAL("_In_")],
                         TokenHandle: Annotated[P[HANDLE], SAL("_Out_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwOpenResourceManager(dp: Dumpulator,
                          ResourceManagerHandle: Annotated[P[HANDLE], SAL("_Out_")],
                          DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                          TmHandle: Annotated[HANDLE, SAL("_In_")],
                          ResourceManagerGuid: Annotated[P[GUID], SAL("_In_opt_")],
                          ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")]
                          ):
    raise NotImplementedError()

@syscall
def ZwOpenSection(dp: Dumpulator,
                  SectionHandle: Annotated[P[HANDLE], SAL("_Out_")],
                  DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                  ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")]
                  ):
    raise NotImplementedError()

@syscall
def ZwOpenSemaphore(dp: Dumpulator,
                    SemaphoreHandle: Annotated[P[HANDLE], SAL("_Out_")],
                    DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                    ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")]
                    ):
    raise NotImplementedError()

@syscall
def ZwOpenSession(dp: Dumpulator,
                  SessionHandle: Annotated[P[HANDLE], SAL("_Out_")],
                  DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                  ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")]
                  ):
    raise NotImplementedError()

@syscall
def ZwOpenSymbolicLinkObject(dp: Dumpulator,
                             LinkHandle: Annotated[P[HANDLE], SAL("_Out_")],
                             DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                             ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")]
                             ):
    raise NotImplementedError()

@syscall
def ZwOpenThread(dp: Dumpulator,
                 ThreadHandle: Annotated[P[HANDLE], SAL("_Out_")],
                 DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                 ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
                 ClientId: Annotated[P[CLIENT_ID], SAL("_In_opt_")]
                 ):
    raise NotImplementedError()

@syscall
def ZwOpenThreadToken(dp: Dumpulator,
                      ThreadHandle: Annotated[HANDLE, SAL("_In_")],
                      DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                      OpenAsSelf: Annotated[BOOLEAN, SAL("_In_")],
                      TokenHandle: Annotated[P[HANDLE], SAL("_Out_")]
                      ):
    raise NotImplementedError()

@syscall
def ZwOpenThreadTokenEx(dp: Dumpulator,
                        ThreadHandle: Annotated[HANDLE, SAL("_In_")],
                        DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                        OpenAsSelf: Annotated[BOOLEAN, SAL("_In_")],
                        HandleAttributes: Annotated[ULONG, SAL("_In_")],
                        TokenHandle: Annotated[P[HANDLE], SAL("_Out_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwOpenTimer(dp: Dumpulator,
                TimerHandle: Annotated[P[HANDLE], SAL("_Out_")],
                DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")]
                ):
    raise NotImplementedError()

@syscall
def ZwOpenTransaction(dp: Dumpulator,
                      TransactionHandle: Annotated[P[HANDLE], SAL("_Out_")],
                      DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                      ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                      Uow: Annotated[P[GUID], SAL("_In_opt_")],
                      TmHandle: Annotated[HANDLE, SAL("_In_opt_")]
                      ):
    raise NotImplementedError()

@syscall
def ZwOpenTransactionManager(dp: Dumpulator,
                             TmHandle: Annotated[P[HANDLE], SAL("_Out_")],
                             DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                             ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_opt_")],
                             LogFileName: Annotated[P[UNICODE_STRING], SAL("_In_opt_")],
                             TmIdentity: Annotated[P[GUID], SAL("_In_opt_")],
                             OpenOptions: Annotated[ULONG, SAL("_In_opt_")]
                             ):
    raise NotImplementedError()

@syscall
def ZwPlugPlayControl(dp: Dumpulator,
                      PnPControlClass: Annotated[PLUGPLAY_CONTROL_CLASS, SAL("_In_")],
                      PnPControlData: Annotated[PVOID, SAL("_Inout_updates_bytes_(PnPControlDataLength)")],
                      PnPControlDataLength: Annotated[ULONG, SAL("_In_")]
                      ):
    raise NotImplementedError()

@syscall
def ZwPowerInformation(dp: Dumpulator,
                       InformationLevel: Annotated[P[OWER_INFORMATION_LEVEL], SAL("_In_")],
                       InputBuffer: Annotated[PVOID, SAL("_In_reads_bytes_opt_(InputBufferLength)")],
                       InputBufferLength: Annotated[ULONG, SAL("_In_")],
                       OutputBuffer: Annotated[PVOID, SAL("_Out_writes_bytes_opt_(OutputBufferLength)")],
                       OutputBufferLength: Annotated[ULONG, SAL("_In_")]
                       ):
    raise NotImplementedError()

@syscall
def ZwPrepareComplete(dp: Dumpulator,
                      EnlistmentHandle: Annotated[HANDLE, SAL("_In_")],
                      TmVirtualClock: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                      ):
    raise NotImplementedError()

@syscall
def ZwPrepareEnlistment(dp: Dumpulator,
                        EnlistmentHandle: Annotated[HANDLE, SAL("_In_")],
                        TmVirtualClock: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwPrePrepareComplete(dp: Dumpulator,
                         EnlistmentHandle: Annotated[HANDLE, SAL("_In_")],
                         TmVirtualClock: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwPrePrepareEnlistment(dp: Dumpulator,
                           EnlistmentHandle: Annotated[HANDLE, SAL("_In_")],
                           TmVirtualClock: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                           ):
    raise NotImplementedError()

@syscall
def ZwPrivilegeCheck(dp: Dumpulator,
                     ClientToken: Annotated[HANDLE, SAL("_In_")],
                     RequiredPrivileges: Annotated[P[PRIVILEGE_SET], SAL("_Inout_")],
                     Result: Annotated[P[BOOLEAN], SAL("_Out_")]
                     ):
    raise NotImplementedError()

@syscall
def ZwPrivilegedServiceAuditAlarm(dp: Dumpulator,
                                  SubsystemName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                                  ServiceName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                                  ClientToken: Annotated[HANDLE, SAL("_In_")],
                                  Privileges: Annotated[P[PRIVILEGE_SET], SAL("_In_")],
                                  AccessGranted: Annotated[BOOLEAN, SAL("_In_")]
                                  ):
    raise NotImplementedError()

@syscall
def ZwPrivilegeObjectAuditAlarm(dp: Dumpulator,
                                SubsystemName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                                HandleId: Annotated[PVOID, SAL("_In_opt_")],
                                ClientToken: Annotated[HANDLE, SAL("_In_")],
                                DesiredAccess: Annotated[ACCESS_MASK, SAL("_In_")],
                                Privileges: Annotated[P[PRIVILEGE_SET], SAL("_In_")],
                                AccessGranted: Annotated[BOOLEAN, SAL("_In_")]
                                ):
    raise NotImplementedError()

@syscall
def ZwPropagationComplete(dp: Dumpulator,
                          ResourceManagerHandle: Annotated[HANDLE, SAL("_In_")],
                          RequestCookie: Annotated[ULONG, SAL("_In_")],
                          BufferLength: Annotated[ULONG, SAL("_In_")],
                          Buffer: Annotated[PVOID, SAL("_In_")]
                          ):
    raise NotImplementedError()

@syscall
def ZwPropagationFailed(dp: Dumpulator,
                        ResourceManagerHandle: Annotated[HANDLE, SAL("_In_")],
                        RequestCookie: Annotated[ULONG, SAL("_In_")],
                        PropStatus: Annotated[NTSTATUS, SAL("_In_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwProtectVirtualMemory(dp: Dumpulator,
                           ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                           BaseAddress: Annotated[P[PVOID], SAL("_Inout_")],
                           RegionSize: Annotated[P[SIZE_T], SAL("_Inout_")],
                           NewProtect: Annotated[ULONG, SAL("_In_")],
                           OldProtect: Annotated[P[ULONG], SAL("_Out_")]
                           ):
    base = BaseAddress.read_ptr() & 0xFFFFFFFFFFFFF000
    size = round_to_pages(RegionSize.read_ptr())
    protect = MemoryProtect(NewProtect)

    print(f"protect {hex(base)}[{hex(size)}] = {protect}")
    old_protect = dp.memory.protect(base, size, protect)
    OldProtect.write_ulong(old_protect.value)
    return STATUS_SUCCESS

@syscall
def ZwPulseEvent(dp: Dumpulator,
                 EventHandle: Annotated[HANDLE, SAL("_In_")],
                 PreviousState: Annotated[P[LONG], SAL("_Out_opt_")]
                 ):
    raise NotImplementedError()

@syscall
def ZwQueryAttributesFile(dp: Dumpulator,
                          ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
                          FileInformation: Annotated[P[FILE_BASIC_INFORMATION], SAL("_Out_")]
                          ):
    assert ObjectAttributes.ptr != 0
    file_name = ObjectAttributes[0].ObjectName[0].read_str()
    print(f"query attributes {file_name}")
    handle = dp.handles.open_file(file_name)
    assert handle is not None
    file_data = dp.handles.get(handle, AbstractFileObject)
    attr = FILE_BASIC_INFORMATION(dp)
    attr.CreationTime = 0
    attr.LastAccessTime = 0
    attr.LastWriteTime = 0
    attr.ChangeTime = 0
    attr.FileAttributes = 0x80  # FILE_ATTRIBUTE_NORMAL
    dp.write(FileInformation.ptr, bytes(attr))
    dp.handles.close(handle)
    return STATUS_SUCCESS

@syscall
def ZwQueryBootEntryOrder(dp: Dumpulator,
                          Ids: Annotated[P[ULONG], SAL("_Out_writes_opt_(*Count)")],
                          Count: Annotated[P[ULONG], SAL("_Inout_")]
                          ):
    raise NotImplementedError()

@syscall
def ZwQueryBootOptions(dp: Dumpulator,
                       BootOptions: Annotated[P[BOOT_OPTIONS], SAL("_Out_writes_bytes_opt_(*BootOptionsLength)")],
                       BootOptionsLength: Annotated[P[ULONG], SAL("_Inout_")]
                       ):
    raise NotImplementedError()

@syscall
def ZwQueryDebugFilterState(dp: Dumpulator,
                            ComponentId: Annotated[ULONG, SAL("_In_")],
                            Level: Annotated[ULONG, SAL("_In_")]
                            ):
    # STATUS_SUCCESS will print debug messages with RaiseException
    return STATUS_NOT_IMPLEMENTED

@syscall
def ZwQueryDefaultLocale(dp: Dumpulator,
                         UserProfile: Annotated[BOOLEAN, SAL("_In_")],
                         DefaultLocaleId: Annotated[P[LCID], SAL("_Out_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwQueryDefaultUILanguage(dp: Dumpulator,
                             DefaultUILanguageId: Annotated[P[LANGID], SAL("_Out_")]
                             ):
    raise NotImplementedError()

@syscall
def ZwQueryDirectoryFile(dp: Dumpulator,
                         FileHandle: Annotated[HANDLE, SAL("_In_")],
                         Event: Annotated[HANDLE, SAL("_In_opt_")],
                         ApcRoutine: Annotated[P[IO_APC_ROUTINE], SAL("_In_opt_")],
                         ApcContext: Annotated[PVOID, SAL("_In_opt_")],
                         IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                         FileInformation: Annotated[PVOID, SAL("_Out_writes_bytes_(Length)")],
                         Length: Annotated[ULONG, SAL("_In_")],
                         FileInformationClass: Annotated[FILE_INFORMATION_CLASS, SAL("_In_")],
                         ReturnSingleEntry: Annotated[BOOLEAN, SAL("_In_")],
                         FileName: Annotated[P[UNICODE_STRING], SAL("_In_opt_")],
                         RestartScan: Annotated[BOOLEAN, SAL("_In_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwQueryDirectoryFileEx(dp: Dumpulator,
                           FileHandle: Annotated[HANDLE, SAL("_In_")],
                           Event: Annotated[HANDLE, SAL("_In_opt_")],
                           ApcRoutine: Annotated[P[IO_APC_ROUTINE], SAL("_In_opt_")],
                           ApcContext: Annotated[PVOID, SAL("_In_opt_")],
                           IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                           FileInformation: Annotated[PVOID, SAL("_Out_writes_bytes_(Length)")],
                           Length: Annotated[ULONG, SAL("_In_")],
                           FileInformationClass: Annotated[FILE_INFORMATION_CLASS, SAL("_In_")],
                           QueryFlags: Annotated[ULONG, SAL("_In_")],
                           FileName: Annotated[P[UNICODE_STRING], SAL("_In_opt_")]
                           ):
    raise NotImplementedError()

@syscall
def ZwQueryDirectoryObject(dp: Dumpulator,
                           DirectoryHandle: Annotated[HANDLE, SAL("_In_")],
                           Buffer: Annotated[PVOID, SAL("_Out_writes_bytes_opt_(Length)")],
                           Length: Annotated[ULONG, SAL("_In_")],
                           ReturnSingleEntry: Annotated[BOOLEAN, SAL("_In_")],
                           RestartScan: Annotated[BOOLEAN, SAL("_In_")],
                           Context: Annotated[P[ULONG], SAL("_Inout_")],
                           ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                           ):
    raise NotImplementedError()

@syscall
def ZwQueryDriverEntryOrder(dp: Dumpulator,
                            Ids: Annotated[P[ULONG], SAL("_Out_writes_opt_(*Count)")],
                            Count: Annotated[P[ULONG], SAL("_Inout_")]
                            ):
    raise NotImplementedError()

@syscall
def ZwQueryEaFile(dp: Dumpulator,
                  FileHandle: Annotated[HANDLE, SAL("_In_")],
                  IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                  Buffer: Annotated[PVOID, SAL("_Out_writes_bytes_(Length)")],
                  Length: Annotated[ULONG, SAL("_In_")],
                  ReturnSingleEntry: Annotated[BOOLEAN, SAL("_In_")],
                  EaList: Annotated[PVOID, SAL("_In_reads_bytes_opt_(EaListLength)")],
                  EaListLength: Annotated[ULONG, SAL("_In_")],
                  EaIndex: Annotated[P[ULONG], SAL("_In_opt_")],
                  RestartScan: Annotated[BOOLEAN, SAL("_In_")]
                  ):
    raise NotImplementedError()

@syscall
def ZwQueryEvent(dp: Dumpulator,
                 EventHandle: Annotated[HANDLE, SAL("_In_")],
                 EventInformationClass: Annotated[EVENT_INFORMATION_CLASS, SAL("_In_")],
                 EventInformation: Annotated[PVOID, SAL("_Out_writes_bytes_(EventInformationLength)")],
                 EventInformationLength: Annotated[ULONG, SAL("_In_")],
                 ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                 ):
    raise NotImplementedError()

@syscall
def ZwQueryFullAttributesFile(dp: Dumpulator,
                              ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
                              FileInformation: Annotated[P[FILE_NETWORK_OPEN_INFORMATION], SAL("_Out_")]
                              ):
    raise NotImplementedError()

@syscall
def ZwQueryInformationAtom(dp: Dumpulator,
                           Atom: Annotated[RTL_ATOM, SAL("_In_")],
                           AtomInformationClass: Annotated[ATOM_INFORMATION_CLASS, SAL("_In_")],
                           AtomInformation: Annotated[PVOID, SAL("_Out_writes_bytes_(AtomInformationLength)")],
                           AtomInformationLength: Annotated[ULONG, SAL("_In_")],
                           ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                           ):
    raise NotImplementedError()

@syscall
def ZwQueryInformationByName(dp: Dumpulator,
                             ObjectAttributes: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
                             IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                             FileInformation: Annotated[PVOID, SAL("_Out_writes_bytes_(Length)")],
                             Length: Annotated[ULONG, SAL("_In_")],
                             FileInformationClass: Annotated[FILE_INFORMATION_CLASS, SAL("_In_")]
                             ):
    raise NotImplementedError()

@syscall
def ZwQueryInformationEnlistment(dp: Dumpulator,
                                 EnlistmentHandle: Annotated[HANDLE, SAL("_In_")],
                                 EnlistmentInformationClass: Annotated[ENLISTMENT_INFORMATION_CLASS, SAL("_In_")],
                                 EnlistmentInformation: Annotated[PVOID, SAL("_Out_writes_bytes_(EnlistmentInformationLength)")],
                                 EnlistmentInformationLength: Annotated[ULONG, SAL("_In_")],
                                 ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                                 ):
    raise NotImplementedError()

@syscall
def ZwQueryInformationFile(dp: Dumpulator,
                           FileHandle: Annotated[HANDLE, SAL("_In_")],
                           IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                           FileInformation: Annotated[PVOID, SAL("_Out_writes_bytes_(Length)")],
                           Length: Annotated[ULONG, SAL("_In_")],
                           FileInformationClass: Annotated[FILE_INFORMATION_CLASS, SAL("_In_")]
                           ):
    if dp.handles.valid(FileHandle):
        if FileInformationClass == FILE_INFORMATION_CLASS.FileStandardInformation:
            assert Length == 0x18
            assert FileInformation != 0
            assert IoStatusBlock != 0

            file = dp.handles.get(FileHandle, AbstractFileObject)

            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/5afa7f66-619c-48f3-955f-68c4ece704ae
            # return FILE_STANDARD_INFORMATION
            end_of_file = 0 if file.data is None else len(file.data)
            alloc_size = end_of_file + (end_of_file % 0x1000)
            number_of_links = 1
            delete_pending = 0
            directory = 0
            reserved = 0

            info = struct.pack("<QQLBBH", alloc_size, end_of_file, number_of_links, delete_pending, directory, reserved)
            FileInformation.write(info)

            # Put the number of bytes written in the status block
            IO_STATUS_BLOCK.write(IoStatusBlock, STATUS_SUCCESS, len(info))
            return STATUS_SUCCESS
        elif FileInformationClass == FILE_INFORMATION_CLASS.FilePositionInformation:
            assert Length == 0x8
            assert FileInformation != 0
            assert IoStatusBlock != 0

            file_handle_data = dp.handles.get(FileHandle, AbstractFileObject)

            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/e3ce4a39-327e-495c-99b6-6b61606b6f16
            # return FILE_POSITION_INFORMATION
            info = struct.pack("<Q", file_handle_data.file_offset)
            FileInformation.write(info)

            # Put the number of bytes written in the status block
            IO_STATUS_BLOCK.write(IoStatusBlock, STATUS_SUCCESS, len(info))
            return STATUS_SUCCESS

    if FileInformationClass == FILE_INFORMATION_CLASS.FileAttributeTagInformation:
        assert Length == 8
        assert FileInformation != 0
        assert IoStatusBlock != 0
        assert dp.ptr_size() == 8  # TODO: implement 32-bit

        # Return file attributes
        FileAttributes = 0x80  # FILE_ATTRIBUTE_NORMAL
        ReparseTag = 0
        info = struct.pack("<II", FileAttributes, ReparseTag)
        FileInformation.write(info)

        # Put the number of bytes written in the status block
        IO_STATUS_BLOCK.write(IoStatusBlock, STATUS_SUCCESS, len(info))
        return STATUS_SUCCESS
    raise NotImplementedError()

@syscall
def ZwQueryInformationJobObject(dp: Dumpulator,
                                JobHandle: Annotated[HANDLE, SAL("_In_opt_")],
                                JobObjectInformationClass: Annotated[JOBOBJECTINFOCLASS, SAL("_In_")],
                                JobObjectInformation: Annotated[PVOID, SAL("_Out_writes_bytes_(JobObjectInformationLength)")],
                                JobObjectInformationLength: Annotated[ULONG, SAL("_In_")],
                                ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                                ):
    raise NotImplementedError()

@syscall
def ZwQueryInformationPort(dp: Dumpulator,
                           PortHandle: Annotated[HANDLE, SAL("_In_")],
                           PortInformationClass: Annotated[PORT_INFORMATION_CLASS, SAL("_In_")],
                           PortInformation: Annotated[PVOID, SAL("_Out_writes_bytes_to_(Length, *ReturnLength)")],
                           Length: Annotated[ULONG, SAL("_In_")],
                           ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                           ):
    raise NotImplementedError()

@syscall
def ZwQueryInformationProcess(dp: Dumpulator,
                              ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                              ProcessInformationClass: Annotated[PROCESSINFOCLASS, SAL("_In_")],
                              ProcessInformation: Annotated[PVOID, SAL("_Out_writes_bytes_(ProcessInformationLength)")],
                              ProcessInformationLength: Annotated[ULONG, SAL("_In_")],
                              ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                              ):
    assert ProcessHandle == dp.NtCurrentProcess()
    if ProcessInformationClass == PROCESSINFOCLASS.ProcessDebugPort:
        assert ProcessInformationLength == dp.ptr_size()
        dp.write_ptr(ProcessInformation.ptr, 0)
        if ReturnLength != 0:
            dp.write_ulong(ReturnLength.ptr, dp.ptr_size())
        return STATUS_SUCCESS
    elif ProcessInformationClass == PROCESSINFOCLASS.ProcessDebugObjectHandle:
        assert ProcessInformationLength == dp.ptr_size()
        dp.write_ptr(ProcessInformation.ptr, 0)
        if ReturnLength != 0:
            dp.write_ulong(ReturnLength.ptr, dp.ptr_size())
        return STATUS_PORT_NOT_SET
    elif ProcessInformationClass == PROCESSINFOCLASS.ProcessDefaultHardErrorMode:
        assert ProcessInformationLength == 4
        dp.write_ulong(ProcessInformation.ptr, 1)
        if ReturnLength.ptr:
            dp.write_ulong(ReturnLength.ptr, 4)
        return STATUS_SUCCESS
    elif ProcessInformationClass == PROCESSINFOCLASS.ProcessExecuteFlags:
        assert ProcessInformationLength == 4
        dp.write_ulong(ProcessInformation.ptr, 0xD)
        if ReturnLength.ptr:
            dp.write_ulong(ReturnLength.ptr, 4)
        return STATUS_SUCCESS
    elif ProcessInformationClass == PROCESSINFOCLASS.ProcessImageInformation:
        sii = SECTION_IMAGE_INFORMATION(dp)
        assert ProcessInformationLength == ctypes.sizeof(sii)
        module = dp.modules[dp.modules.main]
        pe = module.pe
        opt = pe.OPTIONAL_HEADER
        sii.TransferAddress = module.entry
        sii.ZeroBits = 0
        sii.MaximumStackSize = opt.SizeOfStackReserve
        sii.CommittedStackSize = opt.SizeOfStackCommit  # TODO: more might be committed, check PEB
        sii.SubSystemType = opt.Subsystem
        sii.SubSystemMinorVersion = opt.MinorSubsystemVersion
        sii.SubSystemMajorVersion = opt.MajorSubsystemVersion
        sii.MinorOperatingSystemVersion = opt.MinorOperatingSystemVersion
        sii.MajorOperatingSystemVersion = opt.MajorOperatingSystemVersion
        sii.ImageCharacteristics = pe.FILE_HEADER.Characteristics  # TODO
        sii.DllCharacteristics = opt.DllCharacteristics  # TODO
        sii.Machine = pe.FILE_HEADER.Machine
        sii.ImageContainsCode = 1
        sii.ImageFlags = 1  # TODO
        sii.LoaderFlags = 0  # TODO
        sii.ImageFileSize = module.size  # TODO: best we can do?
        sii.CheckSum = opt.CheckSum
        ProcessInformation.write(bytes(sii))
        if ReturnLength.ptr:
            dp.write_ulong(ReturnLength.ptr, ctypes.sizeof(sii))
        return STATUS_SUCCESS
    elif ProcessInformationClass == PROCESSINFOCLASS.ProcessBasicInformation:
        pbi = PROCESS_BASIC_INFORMATION(dp)
        assert ProcessInformationLength == Struct.sizeof(pbi)
        pbi.ExitStatus = 259  # STILL_ACTIVE
        pbi.PebBaseAddress = dp.peb
        pbi.AffinityMask = 0xFFFF
        pbi.BasePriority = 8
        pbi.UniqueProcessId = dp.process_id
        pbi.InheritedFromUniqueProcessId = dp.parent_process_id
        ProcessInformation.write(bytes(pbi))
        if ReturnLength.ptr:
            dp.write_ulong(ReturnLength.ptr, Struct.sizeof(pbi))
        return STATUS_SUCCESS
    elif ProcessInformationClass == PROCESSINFOCLASS.ProcessImageFileNameWin32:
        main_module = dp.modules[dp.modules.main]
        buffer = UNICODE_STRING.create_buffer(main_module.path, ProcessInformation)
        assert ProcessInformationLength >= len(buffer)
        if ReturnLength.ptr:
            dp.write_ulong(ReturnLength.ptr, len(buffer))
        ProcessInformation.write(buffer)
        return STATUS_SUCCESS
    raise NotImplementedError()

@syscall
def ZwQueryInformationResourceManager(dp: Dumpulator,
                                      ResourceManagerHandle: Annotated[HANDLE, SAL("_In_")],
                                      ResourceManagerInformationClass: Annotated[RESOURCEMANAGER_INFORMATION_CLASS, SAL("_In_")],
                                      ResourceManagerInformation: Annotated[PVOID, SAL("_Out_writes_bytes_(ResourceManagerInformationLength)")],
                                      ResourceManagerInformationLength: Annotated[ULONG, SAL("_In_")],
                                      ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                                      ):
    raise NotImplementedError()

@syscall
def ZwQueryInformationThread(dp: Dumpulator,
                             ThreadHandle: Annotated[HANDLE, SAL("_In_")],
                             ThreadInformationClass: Annotated[THREADINFOCLASS, SAL("_In_")],
                             ThreadInformation: Annotated[PVOID, SAL("_Out_writes_bytes_(ThreadInformationLength)")],
                             ThreadInformationLength: Annotated[ULONG, SAL("_In_")],
                             ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                             ):
    if ThreadInformationClass == THREADINFOCLASS.ThreadDynamicCodePolicyInfo:
        assert ThreadInformationLength == 4
        assert ReturnLength == 0
        dp.write_ulong(ThreadInformation, 0)
        return STATUS_SUCCESS
    raise Exception()

@syscall
def ZwQueryInformationToken(dp: Dumpulator,
                            TokenHandle: Annotated[HANDLE, SAL("_In_")],
                            TokenInformationClass: Annotated[TOKEN_INFORMATION_CLASS, SAL("_In_")],
                            TokenInformation: Annotated[PVOID, SAL("_Out_writes_bytes_to_opt_(TokenInformationLength, *ReturnLength)")],
                            TokenInformationLength: Annotated[ULONG, SAL("_In_")],
                            ReturnLength: Annotated[P[ULONG], SAL("_Out_")]
                            ):
    raise NotImplementedError()

@syscall
def ZwQueryInformationTransaction(dp: Dumpulator,
                                  TransactionHandle: Annotated[HANDLE, SAL("_In_")],
                                  TransactionInformationClass: Annotated[TRANSACTION_INFORMATION_CLASS, SAL("_In_")],
                                  TransactionInformation: Annotated[PVOID, SAL("_Out_writes_bytes_(TransactionInformationLength)")],
                                  TransactionInformationLength: Annotated[ULONG, SAL("_In_")],
                                  ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                                  ):
    raise NotImplementedError()

@syscall
def ZwQueryInformationTransactionManager(dp: Dumpulator,
                                         TransactionManagerHandle: Annotated[HANDLE, SAL("_In_")],
                                         TransactionManagerInformationClass: Annotated[TRANSACTIONMANAGER_INFORMATION_CLASS, SAL("_In_")],
                                         TransactionManagerInformation: Annotated[PVOID, SAL("_Out_writes_bytes_(TransactionManagerInformationLength)")],
                                         TransactionManagerInformationLength: Annotated[ULONG, SAL("_In_")],
                                         ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                                         ):
    raise NotImplementedError()

@syscall
def ZwQueryInformationWorkerFactory(dp: Dumpulator,
                                    WorkerFactoryHandle: Annotated[HANDLE, SAL("_In_")],
                                    WorkerFactoryInformationClass: Annotated[WORKERFACTORYINFOCLASS, SAL("_In_")],
                                    WorkerFactoryInformation: Annotated[PVOID, SAL("_Out_writes_bytes_(WorkerFactoryInformationLength)")],
                                    WorkerFactoryInformationLength: Annotated[ULONG, SAL("_In_")],
                                    ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                                    ):
    raise NotImplementedError()

@syscall
def ZwQueryInstallUILanguage(dp: Dumpulator,
                             InstallUILanguageId: Annotated[P[LANGID], SAL("_Out_")]
                             ):
    raise NotImplementedError()

@syscall
def ZwQueryIntervalProfile(dp: Dumpulator,
                           ProfileSource: Annotated[KPROFILE_SOURCE, SAL("_In_")],
                           Interval: Annotated[P[ULONG], SAL("_Out_")]
                           ):
    raise NotImplementedError()

@syscall
def ZwQueryIoCompletion(dp: Dumpulator,
                        IoCompletionHandle: Annotated[HANDLE, SAL("_In_")],
                        IoCompletionInformationClass: Annotated[IO_COMPLETION_INFORMATION_CLASS, SAL("_In_")],
                        IoCompletionInformation: Annotated[PVOID, SAL("_Out_writes_bytes_(IoCompletionInformationLength)")],
                        IoCompletionInformationLength: Annotated[ULONG, SAL("_In_")],
                        ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwQueryKey(dp: Dumpulator,
               KeyHandle: Annotated[HANDLE, SAL("_In_")],
               KeyInformationClass: Annotated[KEY_INFORMATION_CLASS, SAL("_In_")],
               KeyInformation: Annotated[PVOID, SAL("_Out_writes_bytes_opt_(Length)")],
               Length: Annotated[ULONG, SAL("_In_")],
               ResultLength: Annotated[P[ULONG], SAL("_Out_")]
               ):
    raise NotImplementedError()

@syscall
def ZwQueryLicenseValue(dp: Dumpulator,
                        ValueName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                        Type: Annotated[P[ULONG], SAL("_Out_opt_")],
                        Data: Annotated[PVOID, SAL("_Out_writes_bytes_to_opt_(DataSize, *ResultDataSize)")],
                        DataSize: Annotated[ULONG, SAL("_In_")],
                        ResultDataSize: Annotated[P[ULONG], SAL("_Out_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwQueryMultipleValueKey(dp: Dumpulator,
                            KeyHandle: Annotated[HANDLE, SAL("_In_")],
                            ValueEntries: Annotated[P[KEY_VALUE_ENTRY], SAL("_Inout_updates_(EntryCount)")],
                            EntryCount: Annotated[ULONG, SAL("_In_")],
                            ValueBuffer: Annotated[PVOID, SAL("_Out_writes_bytes_(*BufferLength)")],
                            BufferLength: Annotated[P[ULONG], SAL("_Inout_")],
                            RequiredBufferLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                            ):
    raise NotImplementedError()

@syscall
def ZwQueryMutant(dp: Dumpulator,
                  MutantHandle: Annotated[HANDLE, SAL("_In_")],
                  MutantInformationClass: Annotated[MUTANT_INFORMATION_CLASS, SAL("_In_")],
                  MutantInformation: Annotated[PVOID, SAL("_Out_writes_bytes_(MutantInformationLength)")],
                  MutantInformationLength: Annotated[ULONG, SAL("_In_")],
                  ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                  ):
    raise NotImplementedError()

@syscall
def ZwQueryObject(dp: Dumpulator,
                  Handle: Annotated[HANDLE, SAL("_In_opt_")],
                  ObjectInformationClass: Annotated[OBJECT_INFORMATION_CLASS, SAL("_In_")],
                  ObjectInformation: Annotated[PVOID, SAL("_Out_writes_bytes_opt_(ObjectInformationLength)")],
                  ObjectInformationLength: Annotated[ULONG, SAL("_In_")],
                  ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                  ):
    if ObjectInformationClass == OBJECT_INFORMATION_CLASS.ObjectHandleFlagInformation:
        assert ObjectInformationLength == 2
        ObjectInformation.write(b'\0\0')
        return STATUS_SUCCESS
    raise NotImplementedError()

@syscall
def ZwQueryOpenSubKeys(dp: Dumpulator,
                       TargetKey: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
                       HandleCount: Annotated[P[ULONG], SAL("_Out_")]
                       ):
    raise NotImplementedError()

@syscall
def ZwQueryOpenSubKeysEx(dp: Dumpulator,
                         TargetKey: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
                         BufferLength: Annotated[ULONG, SAL("_In_")],
                         Buffer: Annotated[PVOID, SAL("_Out_writes_bytes_opt_(BufferLength)")],
                         RequiredSize: Annotated[P[ULONG], SAL("_Out_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwQueryPerformanceCounter(dp: Dumpulator
                              ):
    raise NotImplementedError()

@syscall
def ZwQueryPortInformationProcess(dp: Dumpulator,
                                  PerformanceCounter: Annotated[P[LARGE_INTEGER], SAL("_Out_")]
                                  ):
    raise NotImplementedError()

@syscall
def ZwQueryQuotaInformationFile(dp: Dumpulator,
                                FileHandle: Annotated[HANDLE, SAL("_In_")],
                                IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                                Buffer: Annotated[PVOID, SAL("_Out_writes_bytes_(Length)")],
                                Length: Annotated[ULONG, SAL("_In_")],
                                ReturnSingleEntry: Annotated[BOOLEAN, SAL("_In_")],
                                SidList: Annotated[PVOID, SAL("_In_reads_bytes_opt_(SidListLength)")],
                                SidListLength: Annotated[ULONG, SAL("_In_")],
                                StartSid: Annotated[PSID, SAL("_In_opt_")],
                                RestartScan: Annotated[BOOLEAN, SAL("_In_")]
                                ):
    raise NotImplementedError()

@syscall
def ZwQuerySection(dp: Dumpulator,
                   SectionHandle: Annotated[HANDLE, SAL("_In_")],
                   SectionInformationClass: Annotated[SECTION_INFORMATION_CLASS, SAL("_In_")],
                   SectionInformation: Annotated[PVOID, SAL("_Out_writes_bytes_(SectionInformationLength)")],
                   SectionInformationLength: Annotated[SIZE_T, SAL("_In_")],
                   ReturnLength: Annotated[P[SIZE_T], SAL("_Out_opt_")]
                   ):
    raise NotImplementedError()

@syscall
def ZwQuerySecurityAttributesToken(dp: Dumpulator,
                                   TokenHandle: Annotated[HANDLE, SAL("_In_")],
                                   Attributes: Annotated[P[UNICODE_STRING], SAL("_In_reads_opt_(NumberOfAttributes)")],
                                   NumberOfAttributes: Annotated[ULONG, SAL("_In_")],
                                   Buffer: Annotated[PVOID, SAL("_Out_writes_bytes_(Length)", "PTOKEN_SECURITY_ATTRIBUTES_INFORMATION")],
                                   Length: Annotated[ULONG, SAL("_In_")],
                                   ReturnLength: Annotated[P[ULONG], SAL("_Out_")]
                                   ):
    raise NotImplementedError()

@syscall
def ZwQuerySecurityObject(dp: Dumpulator,
                          Handle: Annotated[HANDLE, SAL("_In_")],
                          SecurityInformation: Annotated[SECURITY_INFORMATION, SAL("_In_")],
                          SecurityDescriptor: Annotated[P[SECURITY_DESCRIPTOR], SAL("_Out_writes_bytes_opt_(Length)")],
                          Length: Annotated[ULONG, SAL("_In_")],
                          LengthNeeded: Annotated[P[ULONG], SAL("_Out_")]
                          ):
    raise NotImplementedError()

@syscall
def ZwQuerySemaphore(dp: Dumpulator,
                     SemaphoreHandle: Annotated[HANDLE, SAL("_In_")],
                     SemaphoreInformationClass: Annotated[SEMAPHORE_INFORMATION_CLASS, SAL("_In_")],
                     SemaphoreInformation: Annotated[PVOID, SAL("_Out_writes_bytes_(SemaphoreInformationLength)")],
                     SemaphoreInformationLength: Annotated[ULONG, SAL("_In_")],
                     ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                     ):
    raise NotImplementedError()

@syscall
def ZwQuerySymbolicLinkObject(dp: Dumpulator,
                              LinkHandle: Annotated[HANDLE, SAL("_In_")],
                              LinkTarget: Annotated[P[UNICODE_STRING], SAL("_Inout_")],
                              ReturnedLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                              ):
    raise NotImplementedError()

@syscall
def ZwQuerySystemEnvironmentValue(dp: Dumpulator,
                                  VariableName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                                  VariableValue: Annotated[PWSTR, SAL("_Out_writes_bytes_(ValueLength)")],
                                  ValueLength: Annotated[USHORT, SAL("_In_")],
                                  ReturnLength: Annotated[P[USHORT], SAL("_Out_opt_")]
                                  ):
    raise NotImplementedError()

@syscall
def ZwQuerySystemEnvironmentValueEx(dp: Dumpulator,
                                    VariableName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                                    VendorGuid: Annotated[P[GUID], SAL("_In_")],
                                    Value: Annotated[PVOID, SAL("_Out_writes_bytes_opt_(*ValueLength)")],
                                    ValueLength: Annotated[P[ULONG], SAL("_Inout_")],
                                    Attributes: Annotated[P[ULONG], SAL("_Out_opt_", "EFI_VARIABLE_*")]
                                    ):
    raise NotImplementedError()

@syscall
def ZwQuerySystemInformation(dp: Dumpulator,
                             SystemInformationClass: Annotated[SYSTEM_INFORMATION_CLASS, SAL("_In_")],
                             SystemInformation: Annotated[PVOID, SAL("_Out_writes_bytes_opt_(SystemInformationLength)")],
                             SystemInformationLength: Annotated[ULONG, SAL("_In_")],
                             ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                             ):
    raise NotImplementedError()

@syscall
def ZwQuerySystemInformationEx(dp: Dumpulator,
                               SystemInformationClass: Annotated[SYSTEM_INFORMATION_CLASS, SAL("_In_")],
                               InputBuffer: Annotated[PVOID, SAL("_In_reads_bytes_(InputBufferLength)")],
                               InputBufferLength: Annotated[ULONG, SAL("_In_")],
                               SystemInformation: Annotated[PVOID, SAL("_Out_writes_bytes_opt_(SystemInformationLength)")],
                               SystemInformationLength: Annotated[ULONG, SAL("_In_")],
                               ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                               ):
    raise NotImplementedError()

@syscall
def ZwQuerySystemTime(dp: Dumpulator,
                      SystemTime: Annotated[P[LARGE_INTEGER], SAL("_Out_")]
                      ):
    raise NotImplementedError()

@syscall
def ZwQueryTimer(dp: Dumpulator,
                 TimerHandle: Annotated[HANDLE, SAL("_In_")],
                 TimerInformationClass: Annotated[TIMER_INFORMATION_CLASS, SAL("_In_")],
                 TimerInformation: Annotated[PVOID, SAL("_Out_writes_bytes_(TimerInformationLength)")],
                 TimerInformationLength: Annotated[ULONG, SAL("_In_")],
                 ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                 ):
    raise NotImplementedError()

@syscall
def ZwQueryTimerResolution(dp: Dumpulator,
                           MaximumTime: Annotated[P[ULONG], SAL("_Out_")],
                           MinimumTime: Annotated[P[ULONG], SAL("_Out_")],
                           CurrentTime: Annotated[P[ULONG], SAL("_Out_")]
                           ):
    raise NotImplementedError()

@syscall
def ZwQueryValueKey(dp: Dumpulator,
                    KeyHandle: Annotated[HANDLE, SAL("_In_")],
                    ValueName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                    KeyValueInformationClass: Annotated[KEY_VALUE_INFORMATION_CLASS, SAL("_In_")],
                    KeyValueInformation: Annotated[PVOID, SAL("_Out_writes_bytes_opt_(Length)")],
                    Length: Annotated[ULONG, SAL("_In_")],
                    ResultLength: Annotated[P[ULONG], SAL("_Out_")]
                    ):
    key = dp.handles.get(KeyHandle, RegistryKeyObject)
    name = ValueName[0].read_str()
    if KeyValueInformationClass == KEY_VALUE_INFORMATION_CLASS.KeyValueFullInformation:
        value = key.values.get(name.lower(), None)
        assert value is not None, "value not found"
        info = KEY_VALUE_FULL_INFORMATION()
        info.TitleIndex = 0

        if len(name) == 0:
            info.NameLength = 0
            appended_data = b""
        else:
            name_data = name.encode("utf-16-le")
            info.NameLength = len(name_data)
            appended_data = name_data

        # Align to 4 bytes
        remain = 4 - len(appended_data) % 4
        if remain > 0:
            appended_data += b"\0" * remain
            assert (len(appended_data) % 4) == 0

        if isinstance(value, str):
            info.Type = REG_SZ
            value_data = value.encode("utf-16-le") + b"\0\0"
        elif isinstance(value, int):
            info.Type = REG_DWORD
            value_data = struct.pack("<I", value)
        else:
            raise NotImplementedError()

        info.DataLength = len(value_data)
        info.DataOffset = ctypes.sizeof(info) + len(appended_data)
        appended_data += value_data

        final_data = bytes(info) + appended_data
        assert len(final_data) <= Length
        if ResultLength != 0:
            dp.write_ulong(ResultLength, len(final_data))
        KeyValueInformation.write(final_data)

        return STATUS_SUCCESS

    raise NotImplementedError()

@syscall
def ZwQueryVirtualMemory(dp: Dumpulator,
                         ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                         BaseAddress: Annotated[PVOID, SAL("_In_opt_")],
                         MemoryInformationClass: Annotated[MEMORY_INFORMATION_CLASS, SAL("_In_")],
                         MemoryInformation: Annotated[PVOID, SAL("_Out_writes_bytes_(MemoryInformationLength)")],
                         MemoryInformationLength: Annotated[SIZE_T, SAL("_In_")],
                         ReturnLength: Annotated[P[SIZE_T], SAL("_Out_opt_")]
                         ):
    assert ProcessHandle == dp.NtCurrentProcess()
    if MemoryInformationClass == MEMORY_INFORMATION_CLASS.MemoryBasicInformation:
        info = dp.memory.query(BaseAddress.ptr)
        mbi = MEMORY_BASIC_INFORMATION(dp)
        assert MemoryInformationLength == ctypes.sizeof(mbi)
        mbi.BaseAddress = info.base
        mbi.AllocationBase = info.allocation_base
        mbi.AllocationProtect = info.allocation_protect.value
        mbi.RegionSize = info.region_size
        mbi.State = info.state.value
        mbi.Protect = info.protect.value
        mbi.Type = info.type.value
        MemoryInformation.write(bytes(mbi))
        if ReturnLength.ptr:
            ReturnLength.write_ulong(ctypes.sizeof(mbi))
        return STATUS_SUCCESS
    elif MemoryInformationClass == MEMORY_INFORMATION_CLASS.MemoryRegionInformation:
        parent_region = dp.memory.find_region(BaseAddress.ptr)
        mri = MEMORY_REGION_INFORMATION(dp)
        mri.AllocationBase = parent_region.start
        mri.AllocationProtect = parent_region.protect.value
        mri.Flags = REGION_MAPPED_IMAGE if parent_region.type == MemoryType.MEM_IMAGE else REGION_PRIVATE
        mri.RegionSize = parent_region.size
        mri.CommitSize = parent_region.size  # TODO
        assert MemoryInformationLength >= ctypes.sizeof(mri)
        MemoryInformation.write(bytes(mri))
        extra_size = MemoryInformationLength - ctypes.sizeof(mri)
        if extra_size > 0:
            dp.write(MemoryInformation.ptr + ctypes.sizeof(mri), b"\x69" * extra_size)
        if ReturnLength.ptr:
            ReturnLength.write_ulong(MemoryInformationLength)
        return STATUS_SUCCESS
    elif MemoryInformationClass == MEMORY_INFORMATION_CLASS.MemoryMappedFilenameInformation:
        # TODO: implement proper UNICODE_STRING type support
        if dp.ptr_size() == 8:
            name = "\\Device\\HarddiskVolume8\\CodeBlocks\\dumpulator\\tests\\ExceptionTest\\x64\\Release\\ExceptionTest.exe"
            ptr = MemoryInformation.ptr + 0x10
            ustr = struct.pack("<HHIQ", len(name) * 2, len(name) * 2 + 1, 0, ptr)
        else:
            name = "\\Device\\HarddiskVolume8\\CodeBlocks\\dumpulator\\tests\\ExceptionTest\\Release\\ExceptionTest.exe"
            ptr = MemoryInformation.ptr + 0x8
            ustr = struct.pack("<HHI", len(name) * 2, len(name) * 2 + 1, ptr)
        data = ustr + name.encode("utf-16-le")
        assert MemoryInformationLength >= len(data)
        MemoryInformation.write(data)
        if ReturnLength.ptr:
            ReturnLength.write_ulong(len(data))
        return STATUS_SUCCESS
    return STATUS_NOT_IMPLEMENTED

@syscall
def ZwQueryVolumeInformationFile(dp: Dumpulator,
                                 FileHandle: Annotated[HANDLE, SAL("_In_")],
                                 IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                                 FsInformation: Annotated[PVOID, SAL("_Out_writes_bytes_(Length)")],
                                 Length: Annotated[ULONG, SAL("_In_")],
                                 FsInformationClass: Annotated[FSINFOCLASS, SAL("_In_")]
                                 ):
    if FsInformationClass == FSINFOCLASS.FileFsDeviceInformation:
        assert Length == 8
        data = dp.handles.get(FileHandle, AbstractFileObject)
        if isinstance(data, ConsoleFileObject):
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/616b66d5-b335-4e1c-8f87-b4a55e8d3e4a
            # FILE_DEVICE_DISK, FILE_CHARACTERISTIC_TS_DEVICE
            result = struct.pack('<II', 0x7, 0x1000)
            FsInformation.write(result)
            IO_STATUS_BLOCK.write(IoStatusBlock, STATUS_SUCCESS, len(result))
            return STATUS_SUCCESS

    raise NotImplementedError()

@syscall
def ZwQueryWnfStateData(dp: Dumpulator,
                        StateName: Annotated[P[CWNF_STATE_NAME], SAL("_In_")],
                        TypeId: Annotated[P[CWNF_TYPE_ID], SAL("_In_opt_")],
                        ExplicitScope: Annotated[PVOID, SAL("_In_opt_")],
                        ChangeStamp: Annotated[P[WNF_CHANGE_STAMP], SAL("_Out_")],
                        Buffer: Annotated[PVOID, SAL("_Out_writes_bytes_to_opt_(*BufferSize, *BufferSize)")],
                        BufferSize: Annotated[P[ULONG], SAL("_Inout_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwQueryWnfStateNameInformation(dp: Dumpulator,
                                   StateName: Annotated[P[CWNF_STATE_NAME], SAL("_In_")],
                                   NameInfoClass: Annotated[WNF_STATE_NAME_INFORMATION, SAL("_In_")],
                                   ExplicitScope: Annotated[PVOID, SAL("_In_opt_")],
                                   InfoBuffer: Annotated[PVOID, SAL("_Out_writes_bytes_(InfoBufferSize)")],
                                   InfoBufferSize: Annotated[ULONG, SAL("_In_")]
                                   ):
    raise NotImplementedError()

@syscall
def ZwQueueApcThread(dp: Dumpulator,
                     ThreadHandle: Annotated[HANDLE, SAL("_In_")],
                     ApcRoutine: Annotated[P[PS_APC_ROUTINE], SAL("_In_")],
                     ApcArgument1: Annotated[PVOID, SAL("_In_opt_")],
                     ApcArgument2: Annotated[PVOID, SAL("_In_opt_")],
                     ApcArgument3: Annotated[PVOID, SAL("_In_opt_")]
                     ):
    raise NotImplementedError()

@syscall
def ZwQueueApcThreadEx(dp: Dumpulator,
                       ThreadHandle: Annotated[HANDLE, SAL("_In_")],
                       ReserveHandle: Annotated[HANDLE, SAL("_In_opt_", "NtAllocateReserveObject")],
                       ApcRoutine: Annotated[P[PS_APC_ROUTINE], SAL("_In_")],
                       ApcArgument1: Annotated[PVOID, SAL("_In_opt_")],
                       ApcArgument2: Annotated[PVOID, SAL("_In_opt_")],
                       ApcArgument3: Annotated[PVOID, SAL("_In_opt_")]
                       ):
    raise NotImplementedError()

@syscall
def ZwQueueApcThreadEx2(dp: Dumpulator,
                        ThreadHandle: Annotated[HANDLE, SAL("_In_")],
                        ReserveHandle: Annotated[HANDLE, SAL("_In_opt_", "NtAllocateReserveObject")],
                        ApcFlags: Annotated[ULONG, SAL("_In_", "QUEUE_USER_APC_FLAGS")],
                        ApcRoutine: Annotated[P[PS_APC_ROUTINE], SAL("_In_")],
                        ApcArgument1: Annotated[PVOID, SAL("_In_opt_")],
                        ApcArgument2: Annotated[PVOID, SAL("_In_opt_")],
                        ApcArgument3: Annotated[PVOID, SAL("_In_opt_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwRaiseException(dp: Dumpulator,
                     ExceptionRecord: Annotated[P[EXCEPTION_RECORD], SAL("_In_")],
                     ContextRecord: Annotated[P[CONTEXT], SAL("_In_")],
                     FirstChance: Annotated[BOOLEAN, SAL("_In_")]
                     ):
    if not FirstChance:
        # Terminate process (RaiseFailFastException)
        exception_code = ExceptionRecord.read_ulong()
        dp.stop(exception_code)
        return STATUS_SUCCESS
    else:
        # TODO: implement raising an exception
        raise NotImplementedError()

@syscall
def ZwRaiseHardError(dp: Dumpulator,
                     ErrorStatus: Annotated[NTSTATUS, SAL("_In_")],
                     NumberOfParameters: Annotated[ULONG, SAL("_In_")],
                     UnicodeStringParameterMask: Annotated[ULONG, SAL("_In_")],
                     Parameters: Annotated[P[ULONG_PTR], SAL("_In_reads_(NumberOfParameters)")],
                     ValidResponseOptions: Annotated[ULONG, SAL("_In_")],
                     Response: Annotated[P[ULONG], SAL("_Out_")]
                     ):
    raise NotImplementedError()

@syscall
def ZwReadFile(dp: Dumpulator,
               FileHandle: Annotated[HANDLE, SAL("_In_")],
               Event: Annotated[HANDLE, SAL("_In_opt_")],
               ApcRoutine: Annotated[P[IO_APC_ROUTINE], SAL("_In_opt_")],
               ApcContext: Annotated[PVOID, SAL("_In_opt_")],
               IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
               Buffer: Annotated[PVOID, SAL("_Out_writes_bytes_(Length)")],
               Length: Annotated[ULONG, SAL("_In_")],
               ByteOffset: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")],
               Key: Annotated[P[ULONG], SAL("_In_opt_")]
               ):
    assert Event == 0
    assert ApcRoutine == 0
    assert ApcContext == 0
    assert ByteOffset == 0
    assert Key == 0
    if dp.handles.valid(FileHandle):
        assert Buffer != 0

        file = dp.handles.get(FileHandle, AbstractFileObject)
        buffer = file.read(Length)

        print(f"reading {file.path}: {buffer}")

        assert len(buffer) <= Length

        Buffer.write(buffer)

        dp.write_ptr(IoStatusBlock.ptr, STATUS_SUCCESS)
        dp.write_ptr(IoStatusBlock.ptr + dp.ptr_size(), len(buffer))

        return STATUS_SUCCESS

    raise NotImplementedError()

@syscall
def ZwReadFileScatter(dp: Dumpulator,
                      FileHandle: Annotated[HANDLE, SAL("_In_")],
                      Event: Annotated[HANDLE, SAL("_In_opt_")],
                      ApcRoutine: Annotated[P[IO_APC_ROUTINE], SAL("_In_opt_")],
                      ApcContext: Annotated[PVOID, SAL("_In_opt_")],
                      IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                      SegmentArray: Annotated[P[FILE_SEGMENT_ELEMENT], SAL("_In_")],
                      Length: Annotated[ULONG, SAL("_In_")],
                      ByteOffset: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")],
                      Key: Annotated[P[ULONG], SAL("_In_opt_")]
                      ):
    raise NotImplementedError()

@syscall
def ZwReadOnlyEnlistment(dp: Dumpulator,
                         EnlistmentHandle: Annotated[HANDLE, SAL("_In_")],
                         TmVirtualClock: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwReadRequestData(dp: Dumpulator,
                      PortHandle: Annotated[HANDLE, SAL("_In_")],
                      Message: Annotated[P[PORT_MESSAGE], SAL("_In_")],
                      DataEntryIndex: Annotated[ULONG, SAL("_In_")],
                      Buffer: Annotated[PVOID, SAL("_Out_writes_bytes_to_(BufferSize, *NumberOfBytesRead)")],
                      BufferSize: Annotated[SIZE_T, SAL("_In_")],
                      NumberOfBytesRead: Annotated[P[SIZE_T], SAL("_Out_opt_")]
                      ):
    raise NotImplementedError()

@syscall
def ZwReadVirtualMemory(dp: Dumpulator,
                        ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                        BaseAddress: Annotated[PVOID, SAL("_In_opt_")],
                        Buffer: Annotated[PVOID, SAL("_Out_writes_bytes_(BufferSize)")],
                        BufferSize: Annotated[SIZE_T, SAL("_In_")],
                        NumberOfBytesRead: Annotated[P[SIZE_T], SAL("_Out_opt_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwRecoverEnlistment(dp: Dumpulator,
                        EnlistmentHandle: Annotated[HANDLE, SAL("_In_")],
                        EnlistmentKey: Annotated[PVOID, SAL("_In_opt_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwRecoverResourceManager(dp: Dumpulator,
                             ResourceManagerHandle: Annotated[HANDLE, SAL("_In_")]
                             ):
    raise NotImplementedError()

@syscall
def ZwRecoverTransactionManager(dp: Dumpulator,
                                TransactionManagerHandle: Annotated[HANDLE, SAL("_In_")]
                                ):
    raise NotImplementedError()

@syscall
def ZwRegisterProtocolAddressInformation(dp: Dumpulator,
                                         ResourceManager: Annotated[HANDLE, SAL("_In_")],
                                         ProtocolId: Annotated[P[CRM_PROTOCOL_ID], SAL("_In_")],
                                         ProtocolInformationSize: Annotated[ULONG, SAL("_In_")],
                                         ProtocolInformation: Annotated[PVOID, SAL("_In_")],
                                         CreateOptions: Annotated[ULONG, SAL("_In_opt_")]
                                         ):
    raise NotImplementedError()

@syscall
def ZwRegisterThreadTerminatePort(dp: Dumpulator,
                                  PortHandle: Annotated[HANDLE, SAL("_In_")]
                                  ):
    raise NotImplementedError()

@syscall
def ZwReleaseCMFViewOwnership(dp: Dumpulator
                              ):
    raise NotImplementedError()

@syscall
def ZwReleaseKeyedEvent(dp: Dumpulator,
                        KeyedEventHandle: Annotated[HANDLE, SAL("_In_")],
                        KeyValue: Annotated[PVOID, SAL("_In_")],
                        Alertable: Annotated[BOOLEAN, SAL("_In_")],
                        Timeout: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwReleaseMutant(dp: Dumpulator,
                    MutantHandle: Annotated[HANDLE, SAL("_In_")],
                    PreviousCount: Annotated[P[LONG], SAL("_Out_opt_")]
                    ):
    raise NotImplementedError()

@syscall
def ZwReleaseSemaphore(dp: Dumpulator,
                       SemaphoreHandle: Annotated[HANDLE, SAL("_In_")],
                       ReleaseCount: Annotated[LONG, SAL("_In_")],
                       PreviousCount: Annotated[P[LONG], SAL("_Out_opt_")]
                       ):
    raise NotImplementedError()

@syscall
def ZwReleaseWorkerFactoryWorker(dp: Dumpulator,
                                 WorkerFactoryHandle: Annotated[HANDLE, SAL("_In_")]
                                 ):
    raise NotImplementedError()

@syscall
def ZwRemoveIoCompletion(dp: Dumpulator,
                         IoCompletionHandle: Annotated[HANDLE, SAL("_In_")],
                         KeyContext: Annotated[P[PVOID], SAL("_Out_")],
                         ApcContext: Annotated[P[PVOID], SAL("_Out_")],
                         IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                         Timeout: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwRemoveIoCompletionEx(dp: Dumpulator,
                           IoCompletionHandle: Annotated[HANDLE, SAL("_In_")],
                           IoCompletionInformation: Annotated[P[FILE_IO_COMPLETION_INFORMATION], SAL("_Out_writes_to_(Count, *NumEntriesRemoved)")],
                           Count: Annotated[ULONG, SAL("_In_")],
                           NumEntriesRemoved: Annotated[P[ULONG], SAL("_Out_")],
                           Timeout: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")],
                           Alertable: Annotated[BOOLEAN, SAL("_In_")]
                           ):
    raise NotImplementedError()

@syscall
def ZwRemoveProcessDebug(dp: Dumpulator,
                         ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                         DebugObjectHandle: Annotated[HANDLE, SAL("_In_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwRenameKey(dp: Dumpulator,
                KeyHandle: Annotated[HANDLE, SAL("_In_")],
                NewName: Annotated[P[UNICODE_STRING], SAL("_In_")]
                ):
    raise NotImplementedError()

@syscall
def ZwRenameTransactionManager(dp: Dumpulator,
                               LogFileName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                               ExistingTransactionManagerGuid: Annotated[P[GUID], SAL("_In_")]
                               ):
    raise NotImplementedError()

@syscall
def ZwReplaceKey(dp: Dumpulator,
                 NewFile: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
                 TargetHandle: Annotated[HANDLE, SAL("_In_")],
                 OldFile: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")]
                 ):
    raise NotImplementedError()

@syscall
def ZwReplacePartitionUnit(dp: Dumpulator,
                           TargetInstancePath: Annotated[P[UNICODE_STRING], SAL("_In_")],
                           SpareInstancePath: Annotated[P[UNICODE_STRING], SAL("_In_")],
                           Flags: Annotated[ULONG, SAL("_In_")]
                           ):
    raise NotImplementedError()

@syscall
def ZwReplyPort(dp: Dumpulator,
                PortHandle: Annotated[HANDLE, SAL("_In_")],
                ReplyMessage: Annotated[P[PORT_MESSAGE], SAL("_In_reads_bytes_(ReplyMessage->u1.s1.TotalLength)")]
                ):
    raise NotImplementedError()

@syscall
def ZwReplyWaitReceivePort(dp: Dumpulator,
                           PortHandle: Annotated[HANDLE, SAL("_In_")],
                           PortContext: Annotated[P[PVOID], SAL("_Out_opt_")],
                           ReplyMessage: Annotated[P[PORT_MESSAGE], SAL("_In_reads_bytes_opt_(ReplyMessage->u1.s1.TotalLength)")],
                           ReceiveMessage: Annotated[P[PORT_MESSAGE], SAL("_Out_")]
                           ):
    raise NotImplementedError()

@syscall
def ZwReplyWaitReceivePortEx(dp: Dumpulator,
                             PortHandle: Annotated[HANDLE, SAL("_In_")],
                             PortContext: Annotated[P[PVOID], SAL("_Out_opt_")],
                             ReplyMessage: Annotated[P[PORT_MESSAGE], SAL("_In_reads_bytes_opt_(ReplyMessage->u1.s1.TotalLength)")],
                             ReceiveMessage: Annotated[P[PORT_MESSAGE], SAL("_Out_")],
                             Timeout: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                             ):
    raise NotImplementedError()

@syscall
def ZwReplyWaitReplyPort(dp: Dumpulator,
                         PortHandle: Annotated[HANDLE, SAL("_In_")],
                         ReplyMessage: Annotated[P[PORT_MESSAGE], SAL("_Inout_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwRequestPort(dp: Dumpulator,
                  PortHandle: Annotated[HANDLE, SAL("_In_")],
                  RequestMessage: Annotated[P[PORT_MESSAGE], SAL("_In_reads_bytes_(RequestMessage->u1.s1.TotalLength)")]
                  ):
    raise NotImplementedError()

@syscall
def ZwRequestWaitReplyPort(dp: Dumpulator,
                           PortHandle: Annotated[HANDLE, SAL("_In_")],
                           RequestMessage: Annotated[P[PORT_MESSAGE], SAL("_In_reads_bytes_(RequestMessage->u1.s1.TotalLength)")],
                           ReplyMessage: Annotated[P[PORT_MESSAGE], SAL("_Out_")]
                           ):
    raise NotImplementedError()

@syscall
def ZwRequestWakeupLatency(dp: Dumpulator,
                           latency: Annotated[LATENCY_TIME, SAL("_In_")]
                           ):
    raise NotImplementedError()

@syscall
def ZwResetEvent(dp: Dumpulator,
                 EventHandle: Annotated[HANDLE, SAL("_In_")],
                 PreviousState: Annotated[P[LONG], SAL("_Out_opt_")]
                 ):
    raise NotImplementedError()

@syscall
def ZwResetWriteWatch(dp: Dumpulator,
                      ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                      BaseAddress: Annotated[PVOID, SAL("_In_")],
                      RegionSize: Annotated[SIZE_T, SAL("_In_")]
                      ):
    raise NotImplementedError()

@syscall
def ZwRestoreKey(dp: Dumpulator,
                 KeyHandle: Annotated[HANDLE, SAL("_In_")],
                 FileHandle: Annotated[HANDLE, SAL("_In_")],
                 Flags: Annotated[ULONG, SAL("_In_")]
                 ):
    raise NotImplementedError()

@syscall
def ZwResumeProcess(dp: Dumpulator,
                    ProcessHandle: Annotated[HANDLE, SAL("_In_")]
                    ):
    raise NotImplementedError()

@syscall
def ZwResumeThread(dp: Dumpulator,
                   ThreadHandle: Annotated[HANDLE, SAL("_In_")],
                   PreviousSuspendCount: Annotated[P[ULONG], SAL("_Out_opt_")]
                   ):
    raise NotImplementedError()

@syscall
def ZwRevertContainerImpersonation(dp: Dumpulator
                                   ):
    raise NotImplementedError()

@syscall
def ZwRollbackComplete(dp: Dumpulator,
                       EnlistmentHandle: Annotated[HANDLE, SAL("_In_")],
                       TmVirtualClock: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                       ):
    raise NotImplementedError()

@syscall
def ZwRollbackEnlistment(dp: Dumpulator,
                         EnlistmentHandle: Annotated[HANDLE, SAL("_In_")],
                         TmVirtualClock: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwRollbackTransaction(dp: Dumpulator,
                          TransactionHandle: Annotated[HANDLE, SAL("_In_")],
                          Wait: Annotated[BOOLEAN, SAL("_In_")]
                          ):
    raise NotImplementedError()

@syscall
def ZwRollforwardTransactionManager(dp: Dumpulator,
                                    TransactionManagerHandle: Annotated[HANDLE, SAL("_In_")],
                                    TmVirtualClock: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                                    ):
    raise NotImplementedError()

@syscall
def ZwSaveKey(dp: Dumpulator,
              KeyHandle: Annotated[HANDLE, SAL("_In_")],
              FileHandle: Annotated[HANDLE, SAL("_In_")]
              ):
    raise NotImplementedError()

@syscall
def ZwSaveKeyEx(dp: Dumpulator,
                KeyHandle: Annotated[HANDLE, SAL("_In_")],
                FileHandle: Annotated[HANDLE, SAL("_In_")],
                Format: Annotated[ULONG, SAL("_In_")]
                ):
    raise NotImplementedError()

@syscall
def ZwSaveMergedKeys(dp: Dumpulator,
                     HighPrecedenceKeyHandle: Annotated[HANDLE, SAL("_In_")],
                     LowPrecedenceKeyHandle: Annotated[HANDLE, SAL("_In_")],
                     FileHandle: Annotated[HANDLE, SAL("_In_")]
                     ):
    raise NotImplementedError()

@syscall
def ZwSecureConnectPort(dp: Dumpulator,
                        PortHandle: Annotated[P[HANDLE], SAL("_Out_")],
                        PortName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                        SecurityQos: Annotated[P[SECURITY_QUALITY_OF_SERVICE], SAL("_In_")],
                        ClientView: Annotated[P[PORT_VIEW], SAL("_Inout_opt_")],
                        RequiredServerSid: Annotated[PSID, SAL("_In_opt_")],
                        ServerView: Annotated[P[REMOTE_PORT_VIEW], SAL("_Inout_opt_")],
                        MaxMessageLength: Annotated[P[ULONG], SAL("_Out_opt_")],
                        ConnectionInformation: Annotated[PVOID, SAL("_Inout_updates_bytes_to_opt_(*ConnectionInformationLength, *ConnectionInformationLength)")],
                        ConnectionInformationLength: Annotated[P[ULONG], SAL("_Inout_opt_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwSerializeBoot(dp: Dumpulator
                    ):
    raise NotImplementedError()

@syscall
def ZwSetBootEntryOrder(dp: Dumpulator,
                        Ids: Annotated[P[ULONG], SAL("_In_reads_(Count)")],
                        Count: Annotated[ULONG, SAL("_In_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwSetBootOptions(dp: Dumpulator,
                     BootOptions: Annotated[P[BOOT_OPTIONS], SAL("_In_")],
                     FieldsToChange: Annotated[ULONG, SAL("_In_")]
                     ):
    raise NotImplementedError()

@syscall
def ZwSetCachedSigningLevel(dp: Dumpulator,
                            Flags: Annotated[ULONG, SAL("_In_")],
                            InputSigningLevel: Annotated[SE_SIGNING_LEVEL, SAL("_In_")],
                            SourceFiles: Annotated[P[HANDLE], SAL("_In_reads_(SourceFileCount)")],
                            SourceFileCount: Annotated[ULONG, SAL("_In_")],
                            TargetFile: Annotated[HANDLE, SAL("_In_opt_")]
                            ):
    raise NotImplementedError()

@syscall
def ZwSetContextThread(dp: Dumpulator,
                       ThreadHandle: Annotated[HANDLE, SAL("_In_")],
                       ThreadContext: Annotated[P[CONTEXT], SAL("_In_")]
                       ):
    raise NotImplementedError()

@syscall
def ZwSetDebugFilterState(dp: Dumpulator,
                          ComponentId: Annotated[ULONG, SAL("_In_")],
                          Level: Annotated[ULONG, SAL("_In_")],
                          State: Annotated[BOOLEAN, SAL("_In_")]
                          ):
    raise NotImplementedError()

@syscall
def ZwSetDefaultHardErrorPort(dp: Dumpulator,
                              DefaultHardErrorPort: Annotated[HANDLE, SAL("_In_")]
                              ):
    raise NotImplementedError()

@syscall
def ZwSetDefaultLocale(dp: Dumpulator,
                       UserProfile: Annotated[BOOLEAN, SAL("_In_")],
                       DefaultLocaleId: Annotated[LCID, SAL("_In_")]
                       ):
    raise NotImplementedError()

@syscall
def ZwSetDefaultUILanguage(dp: Dumpulator,
                           DefaultUILanguageId: Annotated[LANGID, SAL("_In_")]
                           ):
    raise NotImplementedError()

@syscall
def ZwSetDriverEntryOrder(dp: Dumpulator,
                          Ids: Annotated[P[ULONG], SAL("_In_reads_(Count)")],
                          Count: Annotated[ULONG, SAL("_In_")]
                          ):
    raise NotImplementedError()

@syscall
def ZwSetEaFile(dp: Dumpulator,
                FileHandle: Annotated[HANDLE, SAL("_In_")],
                IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                Buffer: Annotated[PVOID, SAL("_In_reads_bytes_(Length)")],
                Length: Annotated[ULONG, SAL("_In_")]
                ):
    raise NotImplementedError()

@syscall
def ZwSetEvent(dp: Dumpulator,
               EventHandle: Annotated[HANDLE, SAL("_In_")],
               PreviousState: Annotated[P[LONG], SAL("_Out_opt_")]
               ):
    return STATUS_SUCCESS

@syscall
def ZwSetEventBoostPriority(dp: Dumpulator,
                            EventHandle: Annotated[HANDLE, SAL("_In_")]
                            ):
    raise NotImplementedError()

@syscall
def ZwSetHighEventPair(dp: Dumpulator,
                       EventPairHandle: Annotated[HANDLE, SAL("_In_")]
                       ):
    raise NotImplementedError()

@syscall
def ZwSetHighWaitLowEventPair(dp: Dumpulator,
                              EventPairHandle: Annotated[HANDLE, SAL("_In_")]
                              ):
    raise NotImplementedError()

@syscall
def ZwSetInformationDebugObject(dp: Dumpulator,
                                DebugObjectHandle: Annotated[HANDLE, SAL("_In_")],
                                DebugObjectInformationClass: Annotated[DEBUGOBJECTINFOCLASS, SAL("_In_")],
                                DebugInformation: Annotated[PVOID, SAL("_In_")],
                                DebugInformationLength: Annotated[ULONG, SAL("_In_")],
                                ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                                ):
    raise NotImplementedError()

@syscall
def ZwSetInformationEnlistment(dp: Dumpulator,
                               EnlistmentHandle: Annotated[HANDLE, SAL("_In_opt_")],
                               EnlistmentInformationClass: Annotated[ENLISTMENT_INFORMATION_CLASS, SAL("_In_")],
                               EnlistmentInformation: Annotated[PVOID, SAL("_In_reads_bytes_(EnlistmentInformationLength)")],
                               EnlistmentInformationLength: Annotated[ULONG, SAL("_In_")]
                               ):
    raise NotImplementedError()

@syscall
def ZwSetInformationFile(dp: Dumpulator,
                         FileHandle: Annotated[HANDLE, SAL("_In_")],
                         IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                         FileInformation: Annotated[PVOID, SAL("_In_reads_bytes_(Length)")],
                         Length: Annotated[ULONG, SAL("_In_")],
                         FileInformationClass: Annotated[FILE_INFORMATION_CLASS, SAL("_In_")]
                         ):
    if dp.handles.valid(FileHandle):
        if FileInformationClass == FILE_INFORMATION_CLASS.FilePositionInformation:
            assert IoStatusBlock.ptr != 0
            assert FileInformation.ptr != 0
            assert Length == 8

            handle_data = dp.handles.get(FileHandle, AbstractFileObject)

            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/e3ce4a39-327e-495c-99b6-6b61606b6f16
            info = FileInformation.read(Length)
            file_offset = struct.unpack("<Q", info)[0]
            print(f"setting file pos of {handle_data.path} to {file_offset}")
            handle_data.file_offset = file_offset

            return STATUS_SUCCESS

    if FileInformationClass == FILE_INFORMATION_CLASS.FileDispositionInformationEx:
        print(f"Delete file {hex(FileHandle)}")
        assert IoStatusBlock.ptr != 0
        assert FileInformation.ptr != 0
        assert Length == 4
        return STATUS_SUCCESS
    elif FileInformationClass == FILE_INFORMATION_CLASS.FileDispositionInformation:
        print(f"Delete file {hex(FileHandle)}")
        assert IoStatusBlock.ptr != 0
        assert FileInformation.ptr != 0
        assert Length == 1
        return STATUS_SUCCESS
    raise NotImplementedError()

@syscall
def ZwSetInformationJobObject(dp: Dumpulator,
                              JobHandle: Annotated[HANDLE, SAL("_In_")],
                              JobObjectInformationClass: Annotated[JOBOBJECTINFOCLASS, SAL("_In_")],
                              JobObjectInformation: Annotated[PVOID, SAL("_In_reads_bytes_(JobObjectInformationLength)")],
                              JobObjectInformationLength: Annotated[ULONG, SAL("_In_")]
                              ):
    raise NotImplementedError()

@syscall
def ZwSetInformationKey(dp: Dumpulator,
                        KeyHandle: Annotated[HANDLE, SAL("_In_")],
                        KeySetInformationClass: Annotated[KEY_SET_INFORMATION_CLASS, SAL("_In_")],
                        KeySetInformation: Annotated[PVOID, SAL("_In_reads_bytes_(KeySetInformationLength)")],
                        KeySetInformationLength: Annotated[ULONG, SAL("_In_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwSetInformationObject(dp: Dumpulator,
                           Handle: Annotated[HANDLE, SAL("_In_")],
                           ObjectInformationClass: Annotated[OBJECT_INFORMATION_CLASS, SAL("_In_")],
                           ObjectInformation: Annotated[PVOID, SAL("_In_reads_bytes_(ObjectInformationLength)")],
                           ObjectInformationLength: Annotated[ULONG, SAL("_In_")]
                           ):
    raise NotImplementedError()

@syscall
def ZwSetInformationProcess(dp: Dumpulator,
                            ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                            ProcessInformationClass: Annotated[PROCESSINFOCLASS, SAL("_In_")],
                            ProcessInformation: Annotated[PVOID, SAL("_In_reads_bytes_(ProcessInformationLength)")],
                            ProcessInformationLength: Annotated[ULONG, SAL("_In_")]
                            ):
    assert ProcessHandle == dp.NtCurrentProcess()
    if ProcessInformationClass == PROCESSINFOCLASS.ProcessConsoleHostProcess:
        return STATUS_SUCCESS
    elif ProcessInformationClass == PROCESSINFOCLASS.ProcessRaiseUMExceptionOnInvalidHandleClose:
        return STATUS_SUCCESS
    elif ProcessInformationClass == PROCESSINFOCLASS.ProcessFaultInformation:
        assert ProcessInformationLength == 8
        # https://github.com/blackhatethicalhacking/sandbox-attacksurface-analysis-tools/blob/946912f55770522ed4a2c957d5f57a6a2e2845df/NtApiDotNet/NtProcessNative.cs#L403
        fault_flags = dp.read_ulong(ProcessInformation.ptr)
        additional_info = dp.read_ulong(ProcessInformation.ptr + 4)
        return STATUS_SUCCESS
    elif ProcessInformationClass == PROCESSINFOCLASS.ProcessLoaderDetour:
        assert ProcessInformationLength == 4
        dp.write_ulong(ProcessInformation, 0)
        return STATUS_SUCCESS
    raise NotImplementedError()

@syscall
def ZwSetInformationResourceManager(dp: Dumpulator,
                                    ResourceManagerHandle: Annotated[HANDLE, SAL("_In_")],
                                    ResourceManagerInformationClass: Annotated[RESOURCEMANAGER_INFORMATION_CLASS, SAL("_In_")],
                                    ResourceManagerInformation: Annotated[PVOID, SAL("_In_reads_bytes_(ResourceManagerInformationLength)")],
                                    ResourceManagerInformationLength: Annotated[ULONG, SAL("_In_")]
                                    ):
    raise NotImplementedError()

@syscall
def ZwSetInformationSymbolicLink(dp: Dumpulator,
                                 LinkHandle: Annotated[HANDLE, SAL("_In_")],
                                 SymbolicLinkInformationClass: Annotated[SYMBOLIC_LINK_INFO_CLASS, SAL("_In_")],
                                 SymbolicLinkInformation: Annotated[PVOID, SAL("_In_reads_bytes_(SymbolicLinkInformationLength)")],
                                 SymbolicLinkInformationLength: Annotated[ULONG, SAL("_In_")]
                                 ):
    raise NotImplementedError()

@syscall
def ZwSetInformationThread(dp: Dumpulator,
                           ThreadHandle: Annotated[HANDLE, SAL("_In_")],
                           ThreadInformationClass: Annotated[THREADINFOCLASS, SAL("_In_")],
                           ThreadInformation: Annotated[PVOID, SAL("_In_reads_bytes_(ThreadInformationLength)")],
                           ThreadInformationLength: Annotated[ULONG, SAL("_In_")]
                           ):
    if ThreadInformationClass == THREADINFOCLASS.ThreadHideFromDebugger:
        assert ThreadInformation == 0
        assert ThreadInformationLength == 0
        assert ThreadHandle == dp.NtCurrentThread()
        return STATUS_SUCCESS
    raise NotImplementedError()

@syscall
def ZwSetInformationToken(dp: Dumpulator,
                          TokenHandle: Annotated[HANDLE, SAL("_In_")],
                          TokenInformationClass: Annotated[TOKEN_INFORMATION_CLASS, SAL("_In_")],
                          TokenInformation: Annotated[PVOID, SAL("_In_reads_bytes_(TokenInformationLength)")],
                          TokenInformationLength: Annotated[ULONG, SAL("_In_")]
                          ):
    raise NotImplementedError()

@syscall
def ZwSetInformationTransaction(dp: Dumpulator,
                                TransactionHandle: Annotated[HANDLE, SAL("_In_")],
                                TransactionInformationClass: Annotated[TRANSACTION_INFORMATION_CLASS, SAL("_In_")],
                                TransactionInformation: Annotated[PVOID, SAL("_In_reads_bytes_(TransactionInformationLength)")],
                                TransactionInformationLength: Annotated[ULONG, SAL("_In_")]
                                ):
    raise NotImplementedError()

@syscall
def ZwSetInformationTransactionManager(dp: Dumpulator,
                                       TmHandle: Annotated[HANDLE, SAL("_In_opt_")],
                                       TransactionManagerInformationClass: Annotated[TRANSACTIONMANAGER_INFORMATION_CLASS, SAL("_In_")],
                                       TransactionManagerInformation: Annotated[PVOID, SAL("_In_reads_bytes_(TransactionManagerInformationLength)")],
                                       TransactionManagerInformationLength: Annotated[ULONG, SAL("_In_")]
                                       ):
    raise NotImplementedError()

@syscall
def ZwSetInformationVirtualMemory(dp: Dumpulator,
                                  ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                                  VmInformationClass: Annotated[VIRTUAL_MEMORY_INFORMATION_CLASS, SAL("_In_")],
                                  NumberOfEntries: Annotated[ULONG_PTR, SAL("_In_")],
                                  VirtualAddresses: Annotated[P[MEMORY_RANGE_ENTRY], SAL("_In_reads_ (NumberOfEntries)")],
                                  VmInformation: Annotated[PVOID, SAL("_In_reads_bytes_ (VmInformationLength)")],
                                  VmInformationLength: Annotated[ULONG, SAL("_In_")]
                                  ):
    raise NotImplementedError()

@syscall
def ZwSetInformationWorkerFactory(dp: Dumpulator,
                                  WorkerFactoryHandle: Annotated[HANDLE, SAL("_In_")],
                                  WorkerFactoryInformationClass: Annotated[WORKERFACTORYINFOCLASS, SAL("_In_")],
                                  WorkerFactoryInformation: Annotated[PVOID, SAL("_In_reads_bytes_(WorkerFactoryInformationLength)")],
                                  WorkerFactoryInformationLength: Annotated[ULONG, SAL("_In_")]
                                  ):
    raise NotImplementedError()

@syscall
def ZwSetIntervalProfile(dp: Dumpulator,
                         Interval: Annotated[ULONG, SAL("_In_")],
                         Source: Annotated[KPROFILE_SOURCE, SAL("_In_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwSetIoCompletion(dp: Dumpulator,
                      IoCompletionHandle: Annotated[HANDLE, SAL("_In_")],
                      KeyContext: Annotated[PVOID, SAL("_In_opt_")],
                      ApcContext: Annotated[PVOID, SAL("_In_opt_")],
                      IoStatus: Annotated[NTSTATUS, SAL("_In_")],
                      IoStatusInformation: Annotated[ULONG_PTR, SAL("_In_")]
                      ):
    raise NotImplementedError()

@syscall
def ZwSetIoCompletionEx(dp: Dumpulator,
                        IoCompletionHandle: Annotated[HANDLE, SAL("_In_")],
                        IoCompletionPacketHandle: Annotated[HANDLE, SAL("_In_")],
                        KeyContext: Annotated[PVOID, SAL("_In_opt_")],
                        ApcContext: Annotated[PVOID, SAL("_In_opt_")],
                        IoStatus: Annotated[NTSTATUS, SAL("_In_")],
                        IoStatusInformation: Annotated[ULONG_PTR, SAL("_In_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwSetIRTimer(dp: Dumpulator,
                 TimerHandle: Annotated[HANDLE, SAL("_In_")],
                 DueTime: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                 ):
    raise NotImplementedError()

@syscall
def ZwSetLdtEntries(dp: Dumpulator,
                    Selector0: Annotated[ULONG, SAL("_In_")],
                    Entry0Low: Annotated[ULONG, SAL("_In_")],
                    Entry0Hi: Annotated[ULONG, SAL("_In_")],
                    Selector1: Annotated[ULONG, SAL("_In_")],
                    Entry1Low: Annotated[ULONG, SAL("_In_")],
                    Entry1Hi: Annotated[ULONG, SAL("_In_")]
                    ):
    raise NotImplementedError()

@syscall
def ZwSetLowEventPair(dp: Dumpulator,
                      EventPairHandle: Annotated[HANDLE, SAL("_In_")]
                      ):
    raise NotImplementedError()

@syscall
def ZwSetLowWaitHighEventPair(dp: Dumpulator,
                              EventPairHandle: Annotated[HANDLE, SAL("_In_")]
                              ):
    raise NotImplementedError()

@syscall
def ZwSetQuotaInformationFile(dp: Dumpulator,
                              FileHandle: Annotated[HANDLE, SAL("_In_")],
                              IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                              Buffer: Annotated[PVOID, SAL("_In_reads_bytes_(Length)")],
                              Length: Annotated[ULONG, SAL("_In_")]
                              ):
    raise NotImplementedError()

@syscall
def ZwSetSecurityObject(dp: Dumpulator,
                        Handle: Annotated[HANDLE, SAL("_In_")],
                        SecurityInformation: Annotated[SECURITY_INFORMATION, SAL("_In_")],
                        SecurityDescriptor: Annotated[P[SECURITY_DESCRIPTOR], SAL("_In_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwSetSystemEnvironmentValue(dp: Dumpulator,
                                VariableName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                                VariableValue: Annotated[P[UNICODE_STRING], SAL("_In_")]
                                ):
    raise NotImplementedError()

@syscall
def ZwSetSystemEnvironmentValueEx(dp: Dumpulator,
                                  VariableName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                                  VendorGuid: Annotated[P[GUID], SAL("_In_")],
                                  Value: Annotated[PVOID, SAL("_In_reads_bytes_opt_(ValueLength)")],
                                  ValueLength: Annotated[ULONG, SAL("_In_", "0 = delete variable")],
                                  Attributes: Annotated[ULONG, SAL("_In_", "EFI_VARIABLE_*")]
                                  ):
    raise NotImplementedError()

@syscall
def ZwSetSystemInformation(dp: Dumpulator,
                           SystemInformationClass: Annotated[SYSTEM_INFORMATION_CLASS, SAL("_In_")],
                           SystemInformation: Annotated[PVOID, SAL("_In_reads_bytes_opt_(SystemInformationLength)")],
                           SystemInformationLength: Annotated[ULONG, SAL("_In_")]
                           ):
    if SystemInformationClass == SYSTEM_INFORMATION_CLASS.SystemWin32WerStartCallout:
        return STATUS_SUCCESS
    raise NotImplementedError()

@syscall
def ZwSetSystemPowerState(dp: Dumpulator,
                          SystemAction: Annotated[P[OWER_ACTION], SAL("_In_")],
                          LightestSystemState: Annotated[SYSTEM_POWER_STATE, SAL("_In_")],
                          Flags: Annotated[ULONG, SAL("_In_", "POWER_ACTION_* flags")]
                          ):
    raise NotImplementedError()

@syscall
def ZwSetSystemTime(dp: Dumpulator,
                    SystemTime: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")],
                    PreviousTime: Annotated[P[LARGE_INTEGER], SAL("_Out_opt_")]
                    ):
    raise NotImplementedError()

@syscall
def ZwSetThreadExecutionState(dp: Dumpulator,
                              NewFlags: Annotated[EXECUTION_STATE, SAL("_In_", "ES_* flags")],
                              PreviousFlags: Annotated[P[EXECUTION_STATE], SAL("_Out_")]
                              ):
    raise NotImplementedError()

@syscall
def ZwSetTimer(dp: Dumpulator,
               TimerHandle: Annotated[HANDLE, SAL("_In_")],
               DueTime: Annotated[P[LARGE_INTEGER], SAL("_In_")],
               TimerApcRoutine: Annotated[P[TIMER_APC_ROUTINE], SAL("_In_opt_")],
               TimerContext: Annotated[PVOID, SAL("_In_opt_")],
               ResumeTimer: Annotated[BOOLEAN, SAL("_In_")],
               Period: Annotated[LONG, SAL("_In_opt_")],
               PreviousState: Annotated[P[BOOLEAN], SAL("_Out_opt_")]
               ):
    raise NotImplementedError()

@syscall
def ZwSetTimer2(dp: Dumpulator,
                TimerHandle: Annotated[HANDLE, SAL("_In_")],
                DueTime: Annotated[P[LARGE_INTEGER], SAL("_In_")],
                Period: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")],
                Parameters: Annotated[P[T2_SET_PARAMETERS], SAL("_In_")]
                ):
    raise NotImplementedError()

@syscall
def ZwSetTimerEx(dp: Dumpulator,
                 TimerHandle: Annotated[HANDLE, SAL("_In_")],
                 TimerSetInformationClass: Annotated[TIMER_SET_INFORMATION_CLASS, SAL("_In_")],
                 TimerSetInformation: Annotated[PVOID, SAL("_Inout_updates_bytes_opt_(TimerSetInformationLength)")],
                 TimerSetInformationLength: Annotated[ULONG, SAL("_In_")]
                 ):
    raise NotImplementedError()

@syscall
def ZwSetTimerResolution(dp: Dumpulator,
                         DesiredTime: Annotated[ULONG, SAL("_In_")],
                         SetResolution: Annotated[BOOLEAN, SAL("_In_")],
                         ActualTime: Annotated[P[ULONG], SAL("_Out_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwSetUuidSeed(dp: Dumpulator,
                  Seed: Annotated[P[CHAR], SAL("_In_")]
                  ):
    raise NotImplementedError()

@syscall
def ZwSetValueKey(dp: Dumpulator,
                  KeyHandle: Annotated[HANDLE, SAL("_In_")],
                  ValueName: Annotated[P[UNICODE_STRING], SAL("_In_")],
                  TitleIndex: Annotated[ULONG, SAL("_In_opt_")],
                  Type: Annotated[ULONG, SAL("_In_")],
                  Data: Annotated[PVOID, SAL("_In_reads_bytes_opt_(DataSize)")],
                  DataSize: Annotated[ULONG, SAL("_In_")]
                  ):
    raise NotImplementedError()

@syscall
def ZwSetVolumeInformationFile(dp: Dumpulator,
                               FileHandle: Annotated[HANDLE, SAL("_In_")],
                               IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                               FsInformation: Annotated[PVOID, SAL("_In_reads_bytes_(Length)")],
                               Length: Annotated[ULONG, SAL("_In_")],
                               FsInformationClass: Annotated[FSINFOCLASS, SAL("_In_")]
                               ):
    raise NotImplementedError()

@syscall
def ZwSetWnfProcessNotificationEvent(dp: Dumpulator,
                                     NotificationEvent: Annotated[HANDLE, SAL("_In_")]
                                     ):
    raise NotImplementedError()

@syscall
def ZwShutdownSystem(dp: Dumpulator,
                     Action: Annotated[SHUTDOWN_ACTION, SAL("_In_")]
                     ):
    raise NotImplementedError()

@syscall
def ZwShutdownWorkerFactory(dp: Dumpulator,
                            WorkerFactoryHandle: Annotated[HANDLE, SAL("_In_")],
                            PendingWorkerCount: Annotated[P[LONG], SAL("_Inout_")]
                            ):
    raise NotImplementedError()

@syscall
def ZwSignalAndWaitForSingleObject(dp: Dumpulator,
                                   SignalHandle: Annotated[HANDLE, SAL("_In_")],
                                   WaitHandle: Annotated[HANDLE, SAL("_In_")],
                                   Alertable: Annotated[BOOLEAN, SAL("_In_")],
                                   Timeout: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                                   ):
    raise NotImplementedError()

@syscall
def ZwSinglePhaseReject(dp: Dumpulator,
                        EnlistmentHandle: Annotated[HANDLE, SAL("_In_")],
                        TmVirtualClock: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwStartProfile(dp: Dumpulator,
                   ProfileHandle: Annotated[HANDLE, SAL("_In_")]
                   ):
    raise NotImplementedError()

@syscall
def ZwStopProfile(dp: Dumpulator,
                  ProfileHandle: Annotated[HANDLE, SAL("_In_")]
                  ):
    raise NotImplementedError()

@syscall
def ZwSubscribeWnfStateChange(dp: Dumpulator,
                              StateName: Annotated[P[CWNF_STATE_NAME], SAL("_In_")],
                              ChangeStamp: Annotated[WNF_CHANGE_STAMP, SAL("_In_opt_")],
                              EventMask: Annotated[ULONG, SAL("_In_")],
                              SubscriptionId: Annotated[P[ULONG64], SAL("_Out_opt_")]
                              ):
    raise NotImplementedError()

@syscall
def ZwSuspendProcess(dp: Dumpulator,
                     ProcessHandle: Annotated[HANDLE, SAL("_In_")]
                     ):
    raise NotImplementedError()

@syscall
def ZwSuspendThread(dp: Dumpulator,
                    ThreadHandle: Annotated[HANDLE, SAL("_In_")],
                    PreviousSuspendCount: Annotated[P[ULONG], SAL("_Out_opt_")]
                    ):
    raise NotImplementedError()

@syscall
def ZwSystemDebugControl(dp: Dumpulator,
                         Command: Annotated[SYSDBG_COMMAND, SAL("_In_")],
                         InputBuffer: Annotated[PVOID, SAL("_Inout_updates_bytes_opt_(InputBufferLength)")],
                         InputBufferLength: Annotated[ULONG, SAL("_In_")],
                         OutputBuffer: Annotated[PVOID, SAL("_Out_writes_bytes_opt_(OutputBufferLength)")],
                         OutputBufferLength: Annotated[ULONG, SAL("_In_")],
                         ReturnLength: Annotated[P[ULONG], SAL("_Out_opt_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwTerminateEnclave(dp: Dumpulator,
                       BaseAddress: Annotated[PVOID, SAL("_In_")],
                       WaitForThread: Annotated[BOOLEAN, SAL("_In_")]
                       ):
    raise NotImplementedError()

@syscall
def ZwTerminateJobObject(dp: Dumpulator,
                         JobHandle: Annotated[HANDLE, SAL("_In_")],
                         ExitStatus: Annotated[NTSTATUS, SAL("_In_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwTerminateProcess(dp: Dumpulator,
                       ProcessHandle: Annotated[HANDLE, SAL("_In_opt_")],
                       ExitStatus: Annotated[NTSTATUS, SAL("_In_")]
                       ):
    assert ProcessHandle == 0 or ProcessHandle == dp.NtCurrentProcess()
    dp.stop(ExitStatus)

    # TODO: move this to a dedicated helper method
    from .dumpulator import UnicornExceptionInfo, ExceptionType
    exception = UnicornExceptionInfo()
    exception.type = ExceptionType.Terminate
    exception.final = True
    exception.context = dp._uc.context_save()
    return exception

@syscall
def ZwTerminateThread(dp: Dumpulator,
                      ThreadHandle: Annotated[HANDLE, SAL("_In_opt_")],
                      ExitStatus: Annotated[NTSTATUS, SAL("_In_")]
                      ):
    assert ThreadHandle == dp.NtCurrentThread()
    raise NotImplementedError()

@syscall
def ZwTestAlert(dp: Dumpulator
                ):
    raise NotImplementedError()

@syscall
def ZwThawRegistry(dp: Dumpulator
                   ):
    raise NotImplementedError()

@syscall
def ZwThawTransactions(dp: Dumpulator
                       ):
    raise NotImplementedError()

@syscall
def ZwTraceControl(dp: Dumpulator,
                   TraceInformationClass: Annotated[TRACE_CONTROL_INFORMATION_CLASS, SAL("_In_")],
                   InputBuffer: Annotated[PVOID, SAL("_In_reads_bytes_opt_(InputBufferLength)")],
                   InputBufferLength: Annotated[ULONG, SAL("_In_")],
                   TraceInformation: Annotated[PVOID, SAL("_Out_writes_bytes_opt_(TraceInformationLength)")],
                   TraceInformationLength: Annotated[ULONG, SAL("_In_")],
                   ReturnLength: Annotated[P[ULONG], SAL("_Out_")]
                   ):
    raise NotImplementedError()

@syscall
def ZwTraceEvent(dp: Dumpulator,
                 TraceHandle: Annotated[HANDLE, SAL("_In_")],
                 Flags: Annotated[ULONG, SAL("_In_")],
                 FieldSize: Annotated[ULONG, SAL("_In_")],
                 Fields: Annotated[PVOID, SAL("_In_")]
                 ):
    raise NotImplementedError()

@syscall
def ZwTranslateFilePath(dp: Dumpulator,
                        InputFilePath: Annotated[P[FILE_PATH], SAL("_In_")],
                        OutputType: Annotated[ULONG, SAL("_In_")],
                        OutputFilePath: Annotated[P[FILE_PATH], SAL("_Out_writes_bytes_opt_(*OutputFilePathLength)")],
                        OutputFilePathLength: Annotated[P[ULONG], SAL("_Inout_opt_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwUmsThreadYield(dp: Dumpulator,
                     SchedulerParam: Annotated[PVOID, SAL("_In_")]
                     ):
    raise NotImplementedError()

@syscall
def ZwUnloadDriver(dp: Dumpulator,
                   DriverServiceName: Annotated[P[UNICODE_STRING], SAL("_In_")]
                   ):
    raise NotImplementedError()

@syscall
def ZwUnloadKey(dp: Dumpulator,
                TargetKey: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")]
                ):
    raise NotImplementedError()

@syscall
def ZwUnloadKey2(dp: Dumpulator,
                 TargetKey: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
                 Flags: Annotated[ULONG, SAL("_In_")]
                 ):
    raise NotImplementedError()

@syscall
def ZwUnloadKeyEx(dp: Dumpulator,
                  TargetKey: Annotated[P[OBJECT_ATTRIBUTES], SAL("_In_")],
                  Event: Annotated[HANDLE, SAL("_In_opt_")]
                  ):
    raise NotImplementedError()

@syscall
def ZwUnlockFile(dp: Dumpulator,
                 FileHandle: Annotated[HANDLE, SAL("_In_")],
                 IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                 ByteOffset: Annotated[P[LARGE_INTEGER], SAL("_In_")],
                 Length: Annotated[P[LARGE_INTEGER], SAL("_In_")],
                 Key: Annotated[ULONG, SAL("_In_")]
                 ):
    raise NotImplementedError()

@syscall
def ZwUnlockVirtualMemory(dp: Dumpulator,
                          ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                          BaseAddress: Annotated[P[PVOID], SAL("_Inout_")],
                          RegionSize: Annotated[P[SIZE_T], SAL("_Inout_")],
                          MapType: Annotated[ULONG, SAL("_In_")]
                          ):
    raise NotImplementedError()

@syscall
def ZwUnmapViewOfSection(dp: Dumpulator,
                         ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                         BaseAddress: Annotated[PVOID, SAL("_In_opt_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwUnmapViewOfSectionEx(dp: Dumpulator,
                           ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                           BaseAddress: Annotated[PVOID, SAL("_In_opt_")],
                           Flags: Annotated[ULONG, SAL("_In_")]
                           ):
    raise NotImplementedError()

@syscall
def ZwUnsubscribeWnfStateChange(dp: Dumpulator,
                                StateName: Annotated[P[CWNF_STATE_NAME], SAL("_In_")]
                                ):
    raise NotImplementedError()

@syscall
def ZwUpdateWnfStateData(dp: Dumpulator,
                         StateName: Annotated[P[CWNF_STATE_NAME], SAL("_In_")],
                         Buffer: Annotated[PVOID, SAL("_In_reads_bytes_opt_(Length)")],
                         Length: Annotated[ULONG, SAL("_In_opt_")],
                         TypeId: Annotated[P[CWNF_TYPE_ID], SAL("_In_opt_")],
                         ExplicitScope: Annotated[PVOID, SAL("_In_opt_")],
                         MatchingChangeStamp: Annotated[WNF_CHANGE_STAMP, SAL("_In_")],
                         CheckStamp: Annotated[LOGICAL, SAL("_In_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwVdmControl(dp: Dumpulator,
                 Service: Annotated[VDMSERVICECLASS, SAL("_In_")],
                 ServiceData: Annotated[PVOID, SAL("_Inout_")]
                 ):
    raise NotImplementedError()

@syscall
def ZwWaitForAlertByThreadId(dp: Dumpulator,
                             Address: Annotated[PVOID, SAL("_In_")],
                             Timeout: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                             ):
    raise NotImplementedError()

@syscall
def ZwWaitForDebugEvent(dp: Dumpulator,
                        DebugObjectHandle: Annotated[HANDLE, SAL("_In_")],
                        Alertable: Annotated[BOOLEAN, SAL("_In_")],
                        Timeout: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")],
                        WaitStateChange: Annotated[P[DBGUI_WAIT_STATE_CHANGE], SAL("_Out_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwWaitForKeyedEvent(dp: Dumpulator,
                        KeyedEventHandle: Annotated[HANDLE, SAL("_In_")],
                        KeyValue: Annotated[PVOID, SAL("_In_")],
                        Alertable: Annotated[BOOLEAN, SAL("_In_")],
                        Timeout: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwWaitForMultipleObjects(dp: Dumpulator,
                             Count: Annotated[ULONG, SAL("_In_")],
                             Handles: Annotated[P[HANDLE], SAL("_In_reads_(Count)")],
                             WaitType: Annotated[WAIT_TYPE, SAL("_In_")],
                             Alertable: Annotated[BOOLEAN, SAL("_In_")],
                             Timeout: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                             ):
    raise NotImplementedError()

@syscall
def ZwWaitForMultipleObjects32(dp: Dumpulator,
                               Count: Annotated[ULONG, SAL("_In_")],
                               Handles: Annotated[P[LONG], SAL("_In_reads_(Count)")],
                               WaitType: Annotated[WAIT_TYPE, SAL("_In_")],
                               Alertable: Annotated[BOOLEAN, SAL("_In_")],
                               Timeout: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                               ):
    raise NotImplementedError()

@syscall
def ZwWaitForSingleObject(dp: Dumpulator,
                          Handle: Annotated[HANDLE, SAL("_In_")],
                          Alertable: Annotated[BOOLEAN, SAL("_In_")],
                          Timeout: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")]
                          ):
    raise NotImplementedError()

@syscall
def ZwWaitForWorkViaWorkerFactory(dp: Dumpulator,
                                  WorkerFactoryHandle: Annotated[HANDLE, SAL("_In_")],
                                  MiniPackets: Annotated[P[FILE_IO_COMPLETION_INFORMATION], SAL("_Out_writes_to_(Count, *PacketsReturned)")],
                                  Count: Annotated[ULONG, SAL("_In_")],
                                  PacketsReturned: Annotated[P[ULONG], SAL("_Out_")],
                                  DeferredWork: Annotated[P[WORKER_FACTORY_DEFERRED_WORK], SAL("_In_")]
                                  ):
    raise NotImplementedError()

@syscall
def ZwWaitHighEventPair(dp: Dumpulator,
                        EventPairHandle: Annotated[HANDLE, SAL("_In_")]
                        ):
    raise NotImplementedError()

@syscall
def ZwWaitLowEventPair(dp: Dumpulator,
                       EventPairHandle: Annotated[HANDLE, SAL("_In_")]
                       ):
    raise NotImplementedError()

@syscall
def ZwWorkerFactoryWorkerReady(dp: Dumpulator,
                               WorkerFactoryHandle: Annotated[HANDLE, SAL("_In_")]
                               ):
    raise NotImplementedError()

# NOTE: this is not present in phnt
@syscall
def ZwWow64IsProcessorFeaturePresent(dp: Dumpulator,
                                     ProcessorFeature: ULONG
                                     ):
    return 1

@syscall
def ZwWriteFile(dp: Dumpulator,
                FileHandle: Annotated[HANDLE, SAL("_In_")],
                Event: Annotated[HANDLE, SAL("_In_opt_")],
                ApcRoutine: Annotated[P[IO_APC_ROUTINE], SAL("_In_opt_")],
                ApcContext: Annotated[PVOID, SAL("_In_opt_")],
                IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                Buffer: Annotated[PVOID, SAL("_In_reads_bytes_(Length)")],
                Length: Annotated[ULONG, SAL("_In_")],
                ByteOffset: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")],
                Key: Annotated[P[ULONG], SAL("_In_opt_")]
                ):
    assert Event == 0
    assert ApcRoutine == 0
    assert ApcContext == 0
    assert ByteOffset == 0
    assert Key == 0
    if dp.handles.valid(FileHandle):
        assert Buffer != 0

        file = dp.handles.get(FileHandle, AbstractFileObject)
        buffer = bytes(Buffer.read(Length))

        print(f"writing {file.path}: {buffer}")
        file.write(buffer, Length)

        dp.write_ptr(IoStatusBlock.ptr, STATUS_SUCCESS)
        dp.write_ptr(IoStatusBlock.ptr + dp.ptr_size(), len(buffer))

        return STATUS_SUCCESS

    raise NotImplementedError()

@syscall
def ZwWriteFileGather(dp: Dumpulator,
                      FileHandle: Annotated[HANDLE, SAL("_In_")],
                      Event: Annotated[HANDLE, SAL("_In_opt_")],
                      ApcRoutine: Annotated[P[IO_APC_ROUTINE], SAL("_In_opt_")],
                      ApcContext: Annotated[PVOID, SAL("_In_opt_")],
                      IoStatusBlock: Annotated[P[IO_STATUS_BLOCK], SAL("_Out_")],
                      SegmentArray: Annotated[P[FILE_SEGMENT_ELEMENT], SAL("_In_")],
                      Length: Annotated[ULONG, SAL("_In_")],
                      ByteOffset: Annotated[P[LARGE_INTEGER], SAL("_In_opt_")],
                      Key: Annotated[P[ULONG], SAL("_In_opt_")]
                      ):
    raise NotImplementedError()

@syscall
def ZwWriteRequestData(dp: Dumpulator,
                       PortHandle: Annotated[HANDLE, SAL("_In_")],
                       Message: Annotated[P[PORT_MESSAGE], SAL("_In_")],
                       DataEntryIndex: Annotated[ULONG, SAL("_In_")],
                       Buffer: Annotated[PVOID, SAL("_In_reads_bytes_(BufferSize)")],
                       BufferSize: Annotated[SIZE_T, SAL("_In_")],
                       NumberOfBytesWritten: Annotated[P[SIZE_T], SAL("_Out_opt_")]
                       ):
    raise NotImplementedError()

@syscall
def ZwWriteVirtualMemory(dp: Dumpulator,
                         ProcessHandle: Annotated[HANDLE, SAL("_In_")],
                         BaseAddress: Annotated[PVOID, SAL("_In_opt_")],
                         Buffer: Annotated[PVOID, SAL("_In_reads_bytes_(BufferSize)")],
                         BufferSize: Annotated[SIZE_T, SAL("_In_")],
                         NumberOfBytesWritten: Annotated[P[SIZE_T], SAL("_Out_opt_")]
                         ):
    raise NotImplementedError()

@syscall
def ZwYieldExecution(dp: Dumpulator
                     ):
    raise NotImplementedError()

