import struct
import unicorn
from .dumpulator import Dumpulator, syscall_functions
from .native import *


def syscall(func):
    name: str = func.__name__
    if name.startswith("Nt"):
        name = "Zw" + name[2:]
    syscall_functions[name] = func
    return func

@syscall
def ZwAcceptConnectPort(dp: Dumpulator,
                        PortHandle: P(HANDLE),
                        PortContext: PVOID,
                        ConnectionRequest: P(PORT_MESSAGE),
                        AcceptConnection: BOOLEAN,
                        ServerView: P(PORT_VIEW),
                        ClientView: P(REMOTE_PORT_VIEW)
                        ):
    raise NotImplementedError()

@syscall
def ZwAccessCheck(dp: Dumpulator,
                  SecurityDescriptor: P(SECURITY_DESCRIPTOR),
                  ClientToken: HANDLE,
                  DesiredAccess: ACCESS_MASK,
                  GenericMapping: P(GENERIC_MAPPING),
                  PrivilegeSet: P(PRIVILEGE_SET),
                  PrivilegeSetLength: P(ULONG),
                  GrantedAccess: P(ACCESS_MASK),
                  AccessStatus: P(NTSTATUS)
                  ):
    raise NotImplementedError()

@syscall
def ZwAccessCheckAndAuditAlarm(dp: Dumpulator,
                               SubsystemName: P(UNICODE_STRING),
                               HandleId: PVOID,
                               ObjectTypeName: P(UNICODE_STRING),
                               ObjectName: P(UNICODE_STRING),
                               SecurityDescriptor: P(SECURITY_DESCRIPTOR),
                               DesiredAccess: ACCESS_MASK,
                               GenericMapping: P(GENERIC_MAPPING),
                               ObjectCreation: BOOLEAN,
                               GrantedAccess: P(ACCESS_MASK),
                               AccessStatus: P(NTSTATUS),
                               GenerateOnClose: P(BOOLEAN)
                               ):
    raise NotImplementedError()

@syscall
def ZwAccessCheckByType(dp: Dumpulator,
                        SecurityDescriptor: P(SECURITY_DESCRIPTOR),
                        PrincipalSelfSid: PSID,
                        ClientToken: HANDLE,
                        DesiredAccess: ACCESS_MASK,
                        ObjectTypeList: P(OBJECT_TYPE_LIST),
                        ObjectTypeListLength: ULONG,
                        GenericMapping: P(GENERIC_MAPPING),
                        PrivilegeSet: P(PRIVILEGE_SET),
                        PrivilegeSetLength: P(ULONG),
                        GrantedAccess: P(ACCESS_MASK),
                        AccessStatus: P(NTSTATUS)
                        ):
    raise NotImplementedError()

@syscall
def ZwAccessCheckByTypeAndAuditAlarm(dp: Dumpulator,
                                     SubsystemName: P(UNICODE_STRING),
                                     HandleId: PVOID,
                                     ObjectTypeName: P(UNICODE_STRING),
                                     ObjectName: P(UNICODE_STRING),
                                     SecurityDescriptor: P(SECURITY_DESCRIPTOR),
                                     PrincipalSelfSid: PSID,
                                     DesiredAccess: ACCESS_MASK,
                                     AuditType: AUDIT_EVENT_TYPE,
                                     Flags: ULONG,
                                     ObjectTypeList: P(OBJECT_TYPE_LIST),
                                     ObjectTypeListLength: ULONG,
                                     GenericMapping: P(GENERIC_MAPPING),
                                     ObjectCreation: BOOLEAN,
                                     GrantedAccess: P(ACCESS_MASK),
                                     AccessStatus: P(NTSTATUS),
                                     GenerateOnClose: P(BOOLEAN)
                                     ):
    raise NotImplementedError()

@syscall
def ZwAccessCheckByTypeResultList(dp: Dumpulator,
                                  SecurityDescriptor: P(SECURITY_DESCRIPTOR),
                                  PrincipalSelfSid: PSID,
                                  ClientToken: HANDLE,
                                  DesiredAccess: ACCESS_MASK,
                                  ObjectTypeList: P(OBJECT_TYPE_LIST),
                                  ObjectTypeListLength: ULONG,
                                  GenericMapping: P(GENERIC_MAPPING),
                                  PrivilegeSet: P(PRIVILEGE_SET),
                                  PrivilegeSetLength: P(ULONG),
                                  GrantedAccess: P(ACCESS_MASK),
                                  AccessStatus: P(NTSTATUS)
                                  ):
    raise NotImplementedError()

@syscall
def ZwAccessCheckByTypeResultListAndAuditAlarm(dp: Dumpulator,
                                               SubsystemName: P(UNICODE_STRING),
                                               HandleId: PVOID,
                                               ObjectTypeName: P(UNICODE_STRING),
                                               ObjectName: P(UNICODE_STRING),
                                               SecurityDescriptor: P(SECURITY_DESCRIPTOR),
                                               PrincipalSelfSid: PSID,
                                               DesiredAccess: ACCESS_MASK,
                                               AuditType: AUDIT_EVENT_TYPE,
                                               Flags: ULONG,
                                               ObjectTypeList: P(OBJECT_TYPE_LIST),
                                               ObjectTypeListLength: ULONG,
                                               GenericMapping: P(GENERIC_MAPPING),
                                               ObjectCreation: BOOLEAN,
                                               GrantedAccess: P(ACCESS_MASK),
                                               AccessStatus: P(NTSTATUS),
                                               GenerateOnClose: P(BOOLEAN)
                                               ):
    raise NotImplementedError()

@syscall
def ZwAccessCheckByTypeResultListAndAuditAlarmByHandle(dp: Dumpulator,
                                                       SubsystemName: P(UNICODE_STRING),
                                                       HandleId: PVOID,
                                                       ClientToken: HANDLE,
                                                       ObjectTypeName: P(UNICODE_STRING),
                                                       ObjectName: P(UNICODE_STRING),
                                                       SecurityDescriptor: P(SECURITY_DESCRIPTOR),
                                                       PrincipalSelfSid: PSID,
                                                       DesiredAccess: ACCESS_MASK,
                                                       AuditType: AUDIT_EVENT_TYPE,
                                                       Flags: ULONG,
                                                       ObjectTypeList: P(OBJECT_TYPE_LIST),
                                                       ObjectTypeListLength: ULONG,
                                                       GenericMapping: P(GENERIC_MAPPING),
                                                       ObjectCreation: BOOLEAN,
                                                       GrantedAccess: P(ACCESS_MASK),
                                                       AccessStatus: P(NTSTATUS),
                                                       GenerateOnClose: P(BOOLEAN)
                                                       ):
    raise NotImplementedError()

@syscall
def ZwAcquireCMFViewOwnership(dp: Dumpulator,
                              TimeStamp: P(ULONGLONG),
                              tokenTaken: P(BOOLEAN),
                              replaceExisting: BOOLEAN
                              ):
    raise NotImplementedError()

@syscall
def ZwAddAtom(dp: Dumpulator,
              AtomName: PWSTR,
              Length: ULONG,
              Atom: P(RTL_ATOM)
              ):
    raise NotImplementedError()

@syscall
def ZwAddAtomEx(dp: Dumpulator,
                AtomName: PWSTR,
                Length: ULONG,
                Atom: P(RTL_ATOM),
                Flags: ULONG
                ):
    raise NotImplementedError()

@syscall
def ZwAddBootEntry(dp: Dumpulator,
                   BootEntry: P(BOOT_ENTRY),
                   Id: P(ULONG)
                   ):
    raise NotImplementedError()

@syscall
def ZwAddDriverEntry(dp: Dumpulator,
                     DriverEntry: P(EFI_DRIVER_ENTRY),
                     Id: P(ULONG)
                     ):
    raise NotImplementedError()

@syscall
def ZwAdjustGroupsToken(dp: Dumpulator,
                        TokenHandle: HANDLE,
                        ResetToDefault: BOOLEAN,
                        NewState: P(TOKEN_GROUPS),
                        BufferLength: ULONG,
                        PreviousState: P(TOKEN_GROUPS),
                        ReturnLength: P(ULONG)
                        ):
    raise NotImplementedError()

@syscall
def ZwAdjustPrivilegesToken(dp: Dumpulator,
                            TokenHandle: HANDLE,
                            DisableAllPrivileges: BOOLEAN,
                            NewState: P(TOKEN_PRIVILEGES),
                            BufferLength: ULONG,
                            PreviousState: P(TOKEN_PRIVILEGES),
                            ReturnLength: P(ULONG)
                            ):
    raise NotImplementedError()

@syscall
def ZwAdjustTokenClaimsAndDeviceGroups(dp: Dumpulator,
                                       TokenHandle: HANDLE,
                                       UserResetToDefault: BOOLEAN,
                                       DeviceResetToDefault: BOOLEAN,
                                       DeviceGroupsResetToDefault: BOOLEAN,
                                       NewUserState: P(TOKEN_SECURITY_ATTRIBUTES_INFORMATION),
                                       NewDeviceState: P(TOKEN_SECURITY_ATTRIBUTES_INFORMATION),
                                       NewDeviceGroupsState: P(TOKEN_GROUPS),
                                       UserBufferLength: ULONG,
                                       PreviousUserState: P(TOKEN_SECURITY_ATTRIBUTES_INFORMATION),
                                       DeviceBufferLength: ULONG,
                                       PreviousDeviceState: P(TOKEN_SECURITY_ATTRIBUTES_INFORMATION),
                                       DeviceGroupsBufferLength: ULONG,
                                       PreviousDeviceGroups: P(TOKEN_GROUPS),
                                       UserReturnLength: P(ULONG),
                                       DeviceReturnLength: P(ULONG),
                                       DeviceGroupsReturnBufferLength: P(ULONG)
                                       ):
    raise NotImplementedError()

@syscall
def ZwAlertResumeThread(dp: Dumpulator,
                        ThreadHandle: HANDLE,
                        PreviousSuspendCount: P(ULONG)
                        ):
    raise NotImplementedError()

@syscall
def ZwAlertThread(dp: Dumpulator,
                  ThreadHandle: HANDLE
                  ):
    raise NotImplementedError()

@syscall
def ZwAlertThreadByThreadId(dp: Dumpulator,
                            ThreadId: HANDLE
                            ):
    raise NotImplementedError()

@syscall
def ZwAllocateLocallyUniqueId(dp: Dumpulator,
                              Luid: P(LUID)
                              ):
    raise NotImplementedError()

@syscall
def ZwAllocateReserveObject(dp: Dumpulator,
                            MemoryReserveHandle: P(HANDLE),
                            ObjectAttributes: P(OBJECT_ATTRIBUTES),
                            Type: MEMORY_RESERVE_TYPE
                            ):
    raise NotImplementedError()

@syscall
def ZwAllocateUserPhysicalPages(dp: Dumpulator,
                                ProcessHandle: HANDLE,
                                NumberOfPages: P(ULONG_PTR),
                                UserPfnArray: P(ULONG_PTR)
                                ):
    raise NotImplementedError()

@syscall
def ZwAllocateUserPhysicalPagesEx(dp: Dumpulator,
                                  ProcessHandle: HANDLE,
                                  NumberOfPages: P(ULONG_PTR),
                                  UserPfnArray: P(ULONG_PTR),
                                  ExtendedParameters: P(MEM_EXTENDED_PARAMETER),
                                  ExtendedParameterCount: ULONG
                                  ):
    raise NotImplementedError()

@syscall
def ZwAllocateUuids(dp: Dumpulator,
                    Time: P(ULARGE_INTEGER),
                    Range: P(ULONG),
                    Sequence: P(ULONG),
                    Seed: P(CHAR)
                    ):
    raise NotImplementedError()

@syscall
def ZwAllocateVirtualMemory(dp: Dumpulator,
                            ProcessHandle: HANDLE,
                            BaseAddress: P(PVOID),
                            ZeroBits: ULONG_PTR,
                            RegionSize: P(SIZE_T),
                            AllocationType: ULONG,
                            Protect: ULONG
                            ):
    assert ProcessHandle == dp.NtCurrentProcess()
    assert AllocationType == MEM_COMMIT
    assert Protect == PAGE_READWRITE
    base = dp.read_ptr(BaseAddress.ptr)
    size = dp.read_ptr(RegionSize.ptr)
    dp._uc.mem_map(base, size, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
    return STATUS_SUCCESS

@syscall
def ZwAlpcAcceptConnectPort(dp: Dumpulator,
                            PortHandle: P(HANDLE),
                            ConnectionPortHandle: HANDLE,
                            Flags: ULONG,
                            ObjectAttributes: P(OBJECT_ATTRIBUTES),
                            PortAttributes: P(ALPC_PORT_ATTRIBUTES),
                            PortContext: PVOID,
                            ConnectionRequest: P(PORT_MESSAGE),
                            ConnectionMessageAttributes: P(ALPC_MESSAGE_ATTRIBUTES),
                            AcceptConnection: BOOLEAN
                            ):
    raise NotImplementedError()

@syscall
def ZwAlpcCancelMessage(dp: Dumpulator,
                        PortHandle: HANDLE,
                        Flags: ULONG,
                        MessageContext: P(ALPC_CONTEXT_ATTR)
                        ):
    raise NotImplementedError()

@syscall
def ZwAlpcConnectPort(dp: Dumpulator,
                      PortHandle: P(HANDLE),
                      PortName: P(UNICODE_STRING),
                      ObjectAttributes: P(OBJECT_ATTRIBUTES),
                      PortAttributes: P(ALPC_PORT_ATTRIBUTES),
                      Flags: ULONG,
                      RequiredServerSid: PSID,
                      ConnectionMessage: P(PORT_MESSAGE),
                      BufferLength: P(ULONG),
                      OutMessageAttributes: P(ALPC_MESSAGE_ATTRIBUTES),
                      InMessageAttributes: P(ALPC_MESSAGE_ATTRIBUTES),
                      Timeout: P(LARGE_INTEGER)
                      ):
    raise NotImplementedError()

@syscall
def ZwAlpcConnectPortEx(dp: Dumpulator,
                        PortHandle: P(HANDLE),
                        ConnectionPortObjectAttributes: P(OBJECT_ATTRIBUTES),
                        ClientPortObjectAttributes: P(OBJECT_ATTRIBUTES),
                        PortAttributes: P(ALPC_PORT_ATTRIBUTES),
                        Flags: ULONG,
                        ServerSecurityRequirements: P(SECURITY_DESCRIPTOR),
                        ConnectionMessage: P(PORT_MESSAGE),
                        BufferLength: P(SIZE_T),
                        OutMessageAttributes: P(ALPC_MESSAGE_ATTRIBUTES),
                        InMessageAttributes: P(ALPC_MESSAGE_ATTRIBUTES),
                        Timeout: P(LARGE_INTEGER)
                        ):
    raise NotImplementedError()

@syscall
def ZwAlpcCreatePort(dp: Dumpulator,
                     PortHandle: P(HANDLE),
                     ObjectAttributes: P(OBJECT_ATTRIBUTES),
                     PortAttributes: P(ALPC_PORT_ATTRIBUTES)
                     ):
    raise NotImplementedError()

@syscall
def ZwAlpcCreatePortSection(dp: Dumpulator,
                            PortHandle: HANDLE,
                            Flags: ULONG,
                            SectionHandle: HANDLE,
                            SectionSize: SIZE_T,
                            AlpcSectionHandle: P(ALPC_HANDLE),
                            ActualSectionSize: P(SIZE_T)
                            ):
    raise NotImplementedError()

@syscall
def ZwAlpcCreateResourceReserve(dp: Dumpulator,
                                PortHandle: HANDLE,
                                Flags: ULONG,
                                MessageSize: SIZE_T,
                                ResourceId: P(ALPC_HANDLE)
                                ):
    raise NotImplementedError()

@syscall
def ZwAlpcCreateSectionView(dp: Dumpulator,
                            PortHandle: HANDLE,
                            Flags: ULONG,
                            ViewAttributes: P(ALPC_DATA_VIEW_ATTR)
                            ):
    raise NotImplementedError()

@syscall
def ZwAlpcCreateSecurityContext(dp: Dumpulator,
                                PortHandle: HANDLE,
                                Flags: ULONG,
                                SecurityAttribute: P(ALPC_SECURITY_ATTR)
                                ):
    raise NotImplementedError()

@syscall
def ZwAlpcDeletePortSection(dp: Dumpulator,
                            PortHandle: HANDLE,
                            Flags: ULONG,
                            SectionHandle: ALPC_HANDLE
                            ):
    raise NotImplementedError()

@syscall
def ZwAlpcDeleteResourceReserve(dp: Dumpulator,
                                PortHandle: HANDLE,
                                Flags: ULONG,
                                ResourceId: ALPC_HANDLE
                                ):
    raise NotImplementedError()

@syscall
def ZwAlpcDeleteSectionView(dp: Dumpulator,
                            PortHandle: HANDLE,
                            Flags: ULONG,
                            ViewBase: PVOID
                            ):
    raise NotImplementedError()

@syscall
def ZwAlpcDeleteSecurityContext(dp: Dumpulator,
                                PortHandle: HANDLE,
                                Flags: ULONG,
                                ContextHandle: ALPC_HANDLE
                                ):
    raise NotImplementedError()

@syscall
def ZwAlpcDisconnectPort(dp: Dumpulator,
                         PortHandle: HANDLE,
                         Flags: ULONG
                         ):
    raise NotImplementedError()

@syscall
def ZwAlpcImpersonateClientContainerOfPort(dp: Dumpulator,
                                           PortHandle: HANDLE,
                                           Message: P(PORT_MESSAGE),
                                           Flags: ULONG
                                           ):
    raise NotImplementedError()

@syscall
def ZwAlpcImpersonateClientOfPort(dp: Dumpulator,
                                  PortHandle: HANDLE,
                                  Message: P(PORT_MESSAGE),
                                  Flags: PVOID
                                  ):
    raise NotImplementedError()

@syscall
def ZwAlpcOpenSenderProcess(dp: Dumpulator,
                            ProcessHandle: P(HANDLE),
                            PortHandle: HANDLE,
                            PortMessage: P(PORT_MESSAGE),
                            Flags: ULONG,
                            DesiredAccess: ACCESS_MASK,
                            ObjectAttributes: P(OBJECT_ATTRIBUTES)
                            ):
    raise NotImplementedError()

@syscall
def ZwAlpcOpenSenderThread(dp: Dumpulator,
                           ThreadHandle: P(HANDLE),
                           PortHandle: HANDLE,
                           PortMessage: P(PORT_MESSAGE),
                           Flags: ULONG,
                           DesiredAccess: ACCESS_MASK,
                           ObjectAttributes: P(OBJECT_ATTRIBUTES)
                           ):
    raise NotImplementedError()

@syscall
def ZwAlpcQueryInformation(dp: Dumpulator,
                           PortHandle: HANDLE,
                           PortInformationClass: ALPC_PORT_INFORMATION_CLASS,
                           PortInformation: PVOID,
                           Length: ULONG,
                           ReturnLength: P(ULONG)
                           ):
    raise NotImplementedError()

@syscall
def ZwAlpcQueryInformationMessage(dp: Dumpulator,
                                  PortHandle: HANDLE,
                                  PortMessage: P(PORT_MESSAGE),
                                  MessageInformationClass: ALPC_MESSAGE_INFORMATION_CLASS,
                                  MessageInformation: PVOID,
                                  Length: ULONG,
                                  ReturnLength: P(ULONG)
                                  ):
    raise NotImplementedError()

@syscall
def ZwAlpcRevokeSecurityContext(dp: Dumpulator,
                                PortHandle: HANDLE,
                                Flags: ULONG,
                                ContextHandle: ALPC_HANDLE
                                ):
    raise NotImplementedError()

@syscall
def ZwAlpcSendWaitReceivePort(dp: Dumpulator,
                              PortHandle: HANDLE,
                              Flags: ULONG,
                              SendMessageA: P(PORT_MESSAGE),
                              SendMessageAttributes: P(ALPC_MESSAGE_ATTRIBUTES),
                              ReceiveMessage: P(PORT_MESSAGE),
                              BufferLength: P(SIZE_T),
                              ReceiveMessageAttributes: P(ALPC_MESSAGE_ATTRIBUTES),
                              Timeout: P(LARGE_INTEGER)
                              ):
    raise NotImplementedError()

@syscall
def ZwAlpcSetInformation(dp: Dumpulator,
                         PortHandle: HANDLE,
                         PortInformationClass: ALPC_PORT_INFORMATION_CLASS,
                         PortInformation: PVOID,
                         Length: ULONG
                         ):
    raise NotImplementedError()

@syscall
def ZwAreMappedFilesTheSame(dp: Dumpulator,
                            File1MappedAsAnImage: PVOID,
                            File2MappedAsFile: PVOID
                            ):
    raise NotImplementedError()

@syscall
def ZwAssignProcessToJobObject(dp: Dumpulator,
                               JobHandle: HANDLE,
                               ProcessHandle: HANDLE
                               ):
    raise NotImplementedError()

@syscall
def ZwAssociateWaitCompletionPacket(dp: Dumpulator,
                                    WaitCompletionPacketHandle: HANDLE,
                                    IoCompletionHandle: HANDLE,
                                    TargetObjectHandle: HANDLE,
                                    KeyContext: PVOID,
                                    ApcContext: PVOID,
                                    IoStatus: NTSTATUS,
                                    IoStatusInformation: ULONG_PTR,
                                    AlreadySignaled: P(BOOLEAN)
                                    ):
    raise NotImplementedError()

@syscall
def ZwCallbackReturn(dp: Dumpulator,
                     OutputBuffer: PVOID,
                     OutputLength: ULONG,
                     Status: NTSTATUS
                     ):
    raise NotImplementedError()

@syscall
def ZwCallEnclave(dp: Dumpulator,
                  Routine: P(ENCLAVE_ROUTINE),
                  Parameter: PVOID,
                  WaitForThread: BOOLEAN,
                  ReturnValue: P(PVOID)
                  ):
    raise NotImplementedError()

@syscall
def ZwCancelIoFile(dp: Dumpulator,
                   FileHandle: HANDLE,
                   IoStatusBlock: P(IO_STATUS_BLOCK)
                   ):
    raise NotImplementedError()

@syscall
def ZwCancelIoFileEx(dp: Dumpulator,
                     FileHandle: HANDLE,
                     IoRequestToCancel: P(IO_STATUS_BLOCK),
                     IoStatusBlock: P(IO_STATUS_BLOCK)
                     ):
    raise NotImplementedError()

@syscall
def ZwCancelSynchronousIoFile(dp: Dumpulator,
                              ThreadHandle: HANDLE,
                              IoRequestToCancel: P(IO_STATUS_BLOCK),
                              IoStatusBlock: P(IO_STATUS_BLOCK)
                              ):
    raise NotImplementedError()

@syscall
def ZwCancelTimer(dp: Dumpulator,
                  TimerHandle: HANDLE,
                  CurrentState: P(BOOLEAN)
                  ):
    raise NotImplementedError()

@syscall
def ZwCancelTimer2(dp: Dumpulator,
                   TimerHandle: HANDLE,
                   Parameters: P(T2_CANCEL_PARAMETERS)
                   ):
    raise NotImplementedError()

@syscall
def ZwCancelWaitCompletionPacket(dp: Dumpulator,
                                 WaitCompletionPacketHandle: HANDLE,
                                 RemoveSignaledPacket: BOOLEAN
                                 ):
    raise NotImplementedError()

@syscall
def ZwClearEvent(dp: Dumpulator,
                 EventHandle: HANDLE
                 ):
    raise NotImplementedError()

@syscall
def ZwClose(dp: Dumpulator,
            Handle: HANDLE
            ):
    raise NotImplementedError()

@syscall
def ZwCloseObjectAuditAlarm(dp: Dumpulator,
                            SubsystemName: P(UNICODE_STRING),
                            HandleId: PVOID,
                            GenerateOnClose: BOOLEAN
                            ):
    raise NotImplementedError()

@syscall
def ZwCommitComplete(dp: Dumpulator,
                     EnlistmentHandle: HANDLE,
                     TmVirtualClock: P(LARGE_INTEGER)
                     ):
    raise NotImplementedError()

@syscall
def ZwCommitEnlistment(dp: Dumpulator,
                       EnlistmentHandle: HANDLE,
                       TmVirtualClock: P(LARGE_INTEGER)
                       ):
    raise NotImplementedError()

@syscall
def ZwCommitTransaction(dp: Dumpulator,
                        TransactionHandle: HANDLE,
                        Wait: BOOLEAN
                        ):
    raise NotImplementedError()

@syscall
def ZwCompactKeys(dp: Dumpulator,
                  Count: ULONG,
                  KeyArray: P(HANDLE)
                  ):
    raise NotImplementedError()

@syscall
def ZwCompareObjects(dp: Dumpulator,
                     FirstObjectHandle: HANDLE,
                     SecondObjectHandle: HANDLE
                     ):
    raise NotImplementedError()

@syscall
def ZwCompareSigningLevels(dp: Dumpulator,
                           FirstSigningLevel: SE_SIGNING_LEVEL,
                           SecondSigningLevel: SE_SIGNING_LEVEL
                           ):
    raise NotImplementedError()

@syscall
def ZwCompareTokens(dp: Dumpulator,
                    FirstTokenHandle: HANDLE,
                    SecondTokenHandle: HANDLE,
                    Equal: P(BOOLEAN)
                    ):
    raise NotImplementedError()

@syscall
def ZwCompleteConnectPort(dp: Dumpulator,
                          PortHandle: HANDLE
                          ):
    raise NotImplementedError()

@syscall
def ZwCompressKey(dp: Dumpulator,
                  Key: HANDLE
                  ):
    raise NotImplementedError()

@syscall
def ZwConnectPort(dp: Dumpulator,
                  PortHandle: P(HANDLE),
                  PortName: P(UNICODE_STRING),
                  SecurityQos: P(SECURITY_QUALITY_OF_SERVICE),
                  ClientView: P(PORT_VIEW),
                  ServerView: P(REMOTE_PORT_VIEW),
                  MaxMessageLength: P(ULONG),
                  ConnectionInformation: PVOID,
                  ConnectionInformationLength: P(ULONG)
                  ):
    raise NotImplementedError()

@syscall
def ZwContinue(dp: Dumpulator,
               ContextRecord: P(CONTEXT),
               TestAlert: BOOLEAN
               ):
    raise NotImplementedError()

@syscall
def ZwContinueEx(dp: Dumpulator,
                 ContextRecord: P(CONTEXT),
                 ContinueArgument: PVOID
                 ):
    raise NotImplementedError()

@syscall
def ZwCreateDebugObject(dp: Dumpulator,
                        DebugObjectHandle: P(HANDLE),
                        DesiredAccess: ACCESS_MASK,
                        ObjectAttributes: P(OBJECT_ATTRIBUTES),
                        Flags: ULONG
                        ):
    raise NotImplementedError()

@syscall
def ZwCreateDirectoryObject(dp: Dumpulator,
                            DirectoryHandle: P(HANDLE),
                            DesiredAccess: ACCESS_MASK,
                            ObjectAttributes: P(OBJECT_ATTRIBUTES)
                            ):
    raise NotImplementedError()

@syscall
def ZwCreateDirectoryObjectEx(dp: Dumpulator,
                              DirectoryHandle: P(HANDLE),
                              DesiredAccess: ACCESS_MASK,
                              ObjectAttributes: P(OBJECT_ATTRIBUTES),
                              ShadowDirectoryHandle: HANDLE,
                              Flags: ULONG
                              ):
    raise NotImplementedError()

@syscall
def ZwCreateEnclave(dp: Dumpulator,
                    ProcessHandle: HANDLE,
                    BaseAddress: P(PVOID),
                    ZeroBits: ULONG_PTR,
                    Size: SIZE_T,
                    InitialCommitment: SIZE_T,
                    EnclaveType: ULONG,
                    EnclaveInformation: PVOID,
                    EnclaveInformationLength: ULONG,
                    EnclaveError: P(ULONG)
                    ):
    raise NotImplementedError()

@syscall
def ZwCreateEnlistment(dp: Dumpulator,
                       EnlistmentHandle: P(HANDLE),
                       DesiredAccess: ACCESS_MASK,
                       ResourceManagerHandle: HANDLE,
                       TransactionHandle: HANDLE,
                       ObjectAttributes: P(OBJECT_ATTRIBUTES),
                       CreateOptions: ULONG,
                       NotificationMask: NOTIFICATION_MASK,
                       EnlistmentKey: PVOID
                       ):
    raise NotImplementedError()

@syscall
def ZwCreateEvent(dp: Dumpulator,
                  EventHandle: P(HANDLE),
                  DesiredAccess: ACCESS_MASK,
                  ObjectAttributes: P(OBJECT_ATTRIBUTES),
                  EventType: EVENT_TYPE,
                  InitialState: BOOLEAN
                  ):
    raise NotImplementedError()

@syscall
def ZwCreateEventPair(dp: Dumpulator,
                      EventPairHandle: P(HANDLE),
                      DesiredAccess: ACCESS_MASK,
                      ObjectAttributes: P(OBJECT_ATTRIBUTES)
                      ):
    raise NotImplementedError()

@syscall
def ZwCreateFile(dp: Dumpulator,
                 FileHandle: P(HANDLE),
                 DesiredAccess: ACCESS_MASK,
                 ObjectAttributes: P(OBJECT_ATTRIBUTES),
                 IoStatusBlock: P(IO_STATUS_BLOCK),
                 AllocationSize: P(LARGE_INTEGER),
                 FileAttributes: ULONG,
                 ShareAccess: ULONG,
                 CreateDisposition: ULONG,
                 CreateOptions: ULONG,
                 EaBuffer: PVOID,
                 EaLength: ULONG
                 ):
    raise NotImplementedError()

@syscall
def ZwCreateIoCompletion(dp: Dumpulator,
                         IoCompletionHandle: P(HANDLE),
                         DesiredAccess: ACCESS_MASK,
                         ObjectAttributes: P(OBJECT_ATTRIBUTES),
                         Count: ULONG
                         ):
    raise NotImplementedError()

@syscall
def ZwCreateIRTimer(dp: Dumpulator,
                    TimerHandle: P(HANDLE),
                    DesiredAccess: ACCESS_MASK
                    ):
    raise NotImplementedError()

@syscall
def ZwCreateJobObject(dp: Dumpulator,
                      JobHandle: P(HANDLE),
                      DesiredAccess: ACCESS_MASK,
                      ObjectAttributes: P(OBJECT_ATTRIBUTES)
                      ):
    raise NotImplementedError()

@syscall
def ZwCreateJobSet(dp: Dumpulator,
                   NumJob: ULONG,
                   UserJobSet: P(JOB_SET_ARRAY),
                   Flags: ULONG
                   ):
    raise NotImplementedError()

@syscall
def ZwCreateKey(dp: Dumpulator,
                KeyHandle: P(HANDLE),
                DesiredAccess: ACCESS_MASK,
                ObjectAttributes: P(OBJECT_ATTRIBUTES),
                TitleIndex: ULONG,
                Class: P(UNICODE_STRING),
                CreateOptions: ULONG,
                Disposition: P(ULONG)
                ):
    raise NotImplementedError()

@syscall
def ZwCreateKeyedEvent(dp: Dumpulator,
                       KeyedEventHandle: P(HANDLE),
                       DesiredAccess: ACCESS_MASK,
                       ObjectAttributes: P(OBJECT_ATTRIBUTES),
                       Flags: ULONG
                       ):
    raise NotImplementedError()

@syscall
def ZwCreateKeyTransacted(dp: Dumpulator,
                          KeyHandle: P(HANDLE),
                          DesiredAccess: ACCESS_MASK,
                          ObjectAttributes: P(OBJECT_ATTRIBUTES),
                          TitleIndex: ULONG,
                          Class: P(UNICODE_STRING),
                          CreateOptions: ULONG,
                          TransactionHandle: HANDLE,
                          Disposition: P(ULONG)
                          ):
    raise NotImplementedError()

@syscall
def ZwCreateLowBoxToken(dp: Dumpulator,
                        TokenHandle: P(HANDLE),
                        ExistingTokenHandle: HANDLE,
                        DesiredAccess: ACCESS_MASK,
                        ObjectAttributes: P(OBJECT_ATTRIBUTES),
                        PackageSid: PSID,
                        CapabilityCount: ULONG,
                        Capabilities: P(SID_AND_ATTRIBUTES),
                        HandleCount: ULONG,
                        Handles: P(HANDLE)
                        ):
    raise NotImplementedError()

@syscall
def ZwCreateMailslotFile(dp: Dumpulator,
                         FileHandle: P(HANDLE),
                         DesiredAccess: ULONG,
                         ObjectAttributes: P(OBJECT_ATTRIBUTES),
                         IoStatusBlock: P(IO_STATUS_BLOCK),
                         CreateOptions: ULONG,
                         MailslotQuota: ULONG,
                         MaximumMessageSize: ULONG,
                         ReadTimeout: P(LARGE_INTEGER)
                         ):
    raise NotImplementedError()

@syscall
def ZwCreateMutant(dp: Dumpulator,
                   MutantHandle: P(HANDLE),
                   DesiredAccess: ACCESS_MASK,
                   ObjectAttributes: P(OBJECT_ATTRIBUTES),
                   InitialOwner: BOOLEAN
                   ):
    raise NotImplementedError()

@syscall
def ZwCreateNamedPipeFile(dp: Dumpulator,
                          FileHandle: P(HANDLE),
                          DesiredAccess: ULONG,
                          ObjectAttributes: P(OBJECT_ATTRIBUTES),
                          IoStatusBlock: P(IO_STATUS_BLOCK),
                          ShareAccess: ULONG,
                          CreateDisposition: ULONG,
                          CreateOptions: ULONG,
                          NamedPipeType: ULONG,
                          ReadMode: ULONG,
                          CompletionMode: ULONG,
                          MaximumInstances: ULONG,
                          InboundQuota: ULONG,
                          OutboundQuota: ULONG,
                          DefaultTimeout: P(LARGE_INTEGER)
                          ):
    raise NotImplementedError()

@syscall
def ZwCreatePagingFile(dp: Dumpulator,
                       PageFileName: P(UNICODE_STRING),
                       MinimumSize: P(LARGE_INTEGER),
                       MaximumSize: P(LARGE_INTEGER),
                       Priority: ULONG
                       ):
    raise NotImplementedError()

@syscall
def ZwCreatePartition(dp: Dumpulator,
                      PartitionHandle: P(HANDLE),
                      DesiredAccess: ACCESS_MASK,
                      ObjectAttributes: P(OBJECT_ATTRIBUTES),
                      PreferredNode: ULONG
                      ):
    raise NotImplementedError()

@syscall
def ZwCreatePort(dp: Dumpulator,
                 PortHandle: P(HANDLE),
                 ObjectAttributes: P(OBJECT_ATTRIBUTES),
                 MaxConnectionInfoLength: ULONG,
                 MaxMessageLength: ULONG,
                 MaxPoolUsage: ULONG
                 ):
    raise NotImplementedError()

@syscall
def ZwCreatePrivateNamespace(dp: Dumpulator,
                             NamespaceHandle: P(HANDLE),
                             DesiredAccess: ACCESS_MASK,
                             ObjectAttributes: P(OBJECT_ATTRIBUTES),
                             BoundaryDescriptor: PVOID
                             ):
    raise NotImplementedError()

@syscall
def ZwCreateProcess(dp: Dumpulator,
                    ProcessHandle: P(HANDLE),
                    DesiredAccess: ACCESS_MASK,
                    ObjectAttributes: P(OBJECT_ATTRIBUTES),
                    ParentProcess: HANDLE,
                    InheritObjectTable: BOOLEAN,
                    SectionHandle: HANDLE,
                    DebugPort: HANDLE,
                    ExceptionPort: HANDLE
                    ):
    raise NotImplementedError()

@syscall
def ZwCreateProcessEx(dp: Dumpulator,
                      ProcessHandle: P(HANDLE),
                      DesiredAccess: ACCESS_MASK,
                      ObjectAttributes: P(OBJECT_ATTRIBUTES),
                      ParentProcess: HANDLE,
                      Flags: ULONG,
                      SectionHandle: HANDLE,
                      DebugPort: HANDLE,
                      ExceptionPort: HANDLE,
                      JobMemberLevel: ULONG
                      ):
    raise NotImplementedError()

@syscall
def ZwCreateProfile(dp: Dumpulator,
                    ProfileHandle: P(HANDLE),
                    Process: HANDLE,
                    ProfileBase: PVOID,
                    ProfileSize: SIZE_T,
                    BucketSize: ULONG,
                    Buffer: P(ULONG),
                    BufferSize: ULONG,
                    ProfileSource: KPROFILE_SOURCE,
                    Affinity: KAFFINITY
                    ):
    raise NotImplementedError()

@syscall
def ZwCreateProfileEx(dp: Dumpulator,
                      ProfileHandle: P(HANDLE),
                      Process: HANDLE,
                      ProfileBase: PVOID,
                      ProfileSize: SIZE_T,
                      BucketSize: ULONG,
                      Buffer: P(ULONG),
                      BufferSize: ULONG,
                      ProfileSource: KPROFILE_SOURCE,
                      GroupCount: USHORT,
                      GroupAffinity: P(GROUP_AFFINITY)
                      ):
    raise NotImplementedError()

@syscall
def ZwCreateResourceManager(dp: Dumpulator,
                            ResourceManagerHandle: P(HANDLE),
                            DesiredAccess: ACCESS_MASK,
                            TmHandle: HANDLE,
                            RmGuid: P(GUID),
                            ObjectAttributes: P(OBJECT_ATTRIBUTES),
                            CreateOptions: ULONG,
                            Description: P(UNICODE_STRING)
                            ):
    raise NotImplementedError()

@syscall
def ZwCreateSection(dp: Dumpulator,
                    SectionHandle: P(HANDLE),
                    DesiredAccess: ACCESS_MASK,
                    ObjectAttributes: P(OBJECT_ATTRIBUTES),
                    MaximumSize: P(LARGE_INTEGER),
                    SectionPageProtection: ULONG,
                    AllocationAttributes: ULONG,
                    FileHandle: HANDLE
                    ):
    raise NotImplementedError()

@syscall
def ZwCreateSectionEx(dp: Dumpulator,
                      SectionHandle: P(HANDLE),
                      DesiredAccess: ACCESS_MASK,
                      ObjectAttributes: P(OBJECT_ATTRIBUTES),
                      MaximumSize: P(LARGE_INTEGER),
                      SectionPageProtection: ULONG,
                      AllocationAttributes: ULONG,
                      FileHandle: HANDLE,
                      ExtendedParameters: P(MEM_EXTENDED_PARAMETER),
                      ExtendedParameterCount: ULONG
                      ):
    raise NotImplementedError()

@syscall
def ZwCreateSemaphore(dp: Dumpulator,
                      SemaphoreHandle: P(HANDLE),
                      DesiredAccess: ACCESS_MASK,
                      ObjectAttributes: P(OBJECT_ATTRIBUTES),
                      InitialCount: LONG,
                      MaximumCount: LONG
                      ):
    raise NotImplementedError()

@syscall
def ZwCreateSymbolicLinkObject(dp: Dumpulator,
                               LinkHandle: P(HANDLE),
                               DesiredAccess: ACCESS_MASK,
                               ObjectAttributes: P(OBJECT_ATTRIBUTES),
                               LinkTarget: P(UNICODE_STRING)
                               ):
    raise NotImplementedError()

@syscall
def ZwCreateThread(dp: Dumpulator,
                   ThreadHandle: P(HANDLE),
                   DesiredAccess: ACCESS_MASK,
                   ObjectAttributes: P(OBJECT_ATTRIBUTES),
                   ProcessHandle: HANDLE,
                   ClientId: P(CLIENT_ID),
                   ThreadContext: P(CONTEXT),
                   InitialTeb: P(INITIAL_TEB),
                   CreateSuspended: BOOLEAN
                   ):
    raise NotImplementedError()

@syscall
def ZwCreateThreadEx(dp: Dumpulator,
                     ThreadHandle: P(HANDLE),
                     DesiredAccess: ACCESS_MASK,
                     ObjectAttributes: P(OBJECT_ATTRIBUTES),
                     ProcessHandle: HANDLE,
                     StartRoutine: PVOID,
                     Argument: PVOID,
                     CreateFlags: ULONG,
                     ZeroBits: SIZE_T,
                     StackSize: SIZE_T,
                     MaximumStackSize: SIZE_T,
                     AttributeList: P(PS_ATTRIBUTE_LIST)
                     ):
    raise NotImplementedError()

@syscall
def ZwCreateTimer(dp: Dumpulator,
                  TimerHandle: P(HANDLE),
                  DesiredAccess: ACCESS_MASK,
                  ObjectAttributes: P(OBJECT_ATTRIBUTES),
                  TimerType: TIMER_TYPE
                  ):
    raise NotImplementedError()

@syscall
def ZwCreateTimer2(dp: Dumpulator,
                   TimerHandle: P(HANDLE),
                   Reserved1: PVOID,
                   Reserved2: PVOID,
                   Attributes: ULONG,
                   DesiredAccess: ACCESS_MASK
                   ):
    raise NotImplementedError()

@syscall
def ZwCreateToken(dp: Dumpulator,
                  TokenHandle: P(HANDLE),
                  DesiredAccess: ACCESS_MASK,
                  ObjectAttributes: P(OBJECT_ATTRIBUTES),
                  TokenType: TOKEN_TYPE,
                  AuthenticationId: P(LUID),
                  ExpirationTime: P(LARGE_INTEGER),
                  User: P(TOKEN_USER),
                  Groups: P(TOKEN_GROUPS),
                  Privileges: P(TOKEN_PRIVILEGES),
                  Owner: P(TOKEN_OWNER),
                  PrimaryGroup: P(TOKEN_PRIMARY_GROUP),
                  DefaultDacl: P(TOKEN_DEFAULT_DACL),
                  TokenSource: P(TOKEN_SOURCE)
                  ):
    raise NotImplementedError()

@syscall
def ZwCreateTokenEx(dp: Dumpulator,
                    TokenHandle: P(HANDLE),
                    DesiredAccess: ACCESS_MASK,
                    ObjectAttributes: P(OBJECT_ATTRIBUTES),
                    TokenType: TOKEN_TYPE,
                    AuthenticationId: P(LUID),
                    ExpirationTime: P(LARGE_INTEGER),
                    User: P(TOKEN_USER),
                    Groups: P(TOKEN_GROUPS),
                    Privileges: P(TOKEN_PRIVILEGES),
                    UserAttributes: P(TOKEN_SECURITY_ATTRIBUTES_INFORMATION),
                    DeviceAttributes: P(TOKEN_SECURITY_ATTRIBUTES_INFORMATION),
                    DeviceGroups: P(TOKEN_GROUPS),
                    TokenMandatoryPolicy: P(TOKEN_MANDATORY_POLICY),
                    Owner: P(TOKEN_OWNER),
                    PrimaryGroup: P(TOKEN_PRIMARY_GROUP),
                    DefaultDacl: P(TOKEN_DEFAULT_DACL),
                    TokenSource: P(TOKEN_SOURCE)
                    ):
    raise NotImplementedError()

@syscall
def ZwCreateTransaction(dp: Dumpulator,
                        TransactionHandle: P(HANDLE),
                        DesiredAccess: ACCESS_MASK,
                        ObjectAttributes: P(OBJECT_ATTRIBUTES),
                        Uow: P(GUID),
                        TmHandle: HANDLE,
                        CreateOptions: ULONG,
                        IsolationLevel: ULONG,
                        IsolationFlags: ULONG,
                        Timeout: P(LARGE_INTEGER),
                        Description: P(UNICODE_STRING)
                        ):
    raise NotImplementedError()

@syscall
def ZwCreateTransactionManager(dp: Dumpulator,
                               TmHandle: P(HANDLE),
                               DesiredAccess: ACCESS_MASK,
                               ObjectAttributes: P(OBJECT_ATTRIBUTES),
                               LogFileName: P(UNICODE_STRING),
                               CreateOptions: ULONG,
                               CommitStrength: ULONG
                               ):
    raise NotImplementedError()

@syscall
def ZwCreateUserProcess(dp: Dumpulator,
                        ProcessHandle: P(HANDLE),
                        ThreadHandle: P(HANDLE),
                        ProcessDesiredAccess: ACCESS_MASK,
                        ThreadDesiredAccess: ACCESS_MASK,
                        ProcessObjectAttributes: P(OBJECT_ATTRIBUTES),
                        ThreadObjectAttributes: P(OBJECT_ATTRIBUTES),
                        ProcessFlags: ULONG,
                        ThreadFlags: ULONG,
                        ProcessParameters: PVOID,
                        CreateInfo: P(PS_CREATE_INFO),
                        AttributeList: P(PS_ATTRIBUTE_LIST)
                        ):
    raise NotImplementedError()

@syscall
def ZwCreateWaitablePort(dp: Dumpulator,
                         PortHandle: P(HANDLE),
                         ObjectAttributes: P(OBJECT_ATTRIBUTES),
                         MaxConnectionInfoLength: ULONG,
                         MaxMessageLength: ULONG,
                         MaxPoolUsage: ULONG
                         ):
    raise NotImplementedError()

@syscall
def ZwCreateWaitCompletionPacket(dp: Dumpulator,
                                 WaitCompletionPacketHandle: P(HANDLE),
                                 DesiredAccess: ACCESS_MASK,
                                 ObjectAttributes: P(OBJECT_ATTRIBUTES)
                                 ):
    raise NotImplementedError()

@syscall
def ZwCreateWnfStateName(dp: Dumpulator,
                         StateName: P(WNF_STATE_NAME),
                         NameLifetime: WNF_STATE_NAME_LIFETIME,
                         DataScope: WNF_DATA_SCOPE,
                         PersistData: BOOLEAN,
                         TypeId: P(CWNF_TYPE_ID),
                         MaximumStateSize: ULONG,
                         SecurityDescriptor: P(SECURITY_DESCRIPTOR)
                         ):
    raise NotImplementedError()

@syscall
def ZwCreateWorkerFactory(dp: Dumpulator,
                          WorkerFactoryHandleReturn: P(HANDLE),
                          DesiredAccess: ACCESS_MASK,
                          ObjectAttributes: P(OBJECT_ATTRIBUTES),
                          CompletionPortHandle: HANDLE,
                          WorkerProcessHandle: HANDLE,
                          StartRoutine: PVOID,
                          StartParameter: PVOID,
                          MaxThreadCount: ULONG,
                          StackReserve: SIZE_T,
                          StackCommit: SIZE_T
                          ):
    raise NotImplementedError()

@syscall
def ZwDebugActiveProcess(dp: Dumpulator,
                         ProcessHandle: HANDLE,
                         DebugObjectHandle: HANDLE
                         ):
    raise NotImplementedError()

@syscall
def ZwDebugContinue(dp: Dumpulator,
                    DebugObjectHandle: HANDLE,
                    ClientId: P(CLIENT_ID),
                    ContinueStatus: NTSTATUS
                    ):
    raise NotImplementedError()

@syscall
def ZwDelayExecution(dp: Dumpulator,
                     Alertable: BOOLEAN,
                     DelayInterval: P(LARGE_INTEGER)
                     ):
    raise NotImplementedError()

@syscall
def ZwDeleteAtom(dp: Dumpulator,
                 Atom: RTL_ATOM
                 ):
    raise NotImplementedError()

@syscall
def ZwDeleteBootEntry(dp: Dumpulator,
                      Id: ULONG
                      ):
    raise NotImplementedError()

@syscall
def ZwDeleteDriverEntry(dp: Dumpulator,
                        Id: ULONG
                        ):
    raise NotImplementedError()

@syscall
def ZwDeleteFile(dp: Dumpulator,
                 ObjectAttributes: P(OBJECT_ATTRIBUTES)
                 ):
    raise NotImplementedError()

@syscall
def ZwDeleteKey(dp: Dumpulator,
                KeyHandle: HANDLE
                ):
    raise NotImplementedError()

@syscall
def ZwDeleteObjectAuditAlarm(dp: Dumpulator,
                             SubsystemName: P(UNICODE_STRING),
                             HandleId: PVOID,
                             GenerateOnClose: BOOLEAN
                             ):
    raise NotImplementedError()

@syscall
def ZwDeletePrivateNamespace(dp: Dumpulator,
                             NamespaceHandle: HANDLE
                             ):
    raise NotImplementedError()

@syscall
def ZwDeleteValueKey(dp: Dumpulator,
                     KeyHandle: HANDLE,
                     ValueName: P(UNICODE_STRING)
                     ):
    raise NotImplementedError()

@syscall
def ZwDeleteWnfStateData(dp: Dumpulator,
                         StateName: P(CWNF_STATE_NAME),
                         ExplicitScope: PVOID
                         ):
    raise NotImplementedError()

@syscall
def ZwDeleteWnfStateName(dp: Dumpulator,
                         StateName: P(CWNF_STATE_NAME)
                         ):
    raise NotImplementedError()

@syscall
def ZwDeviceIoControlFile(dp: Dumpulator,
                          FileHandle: HANDLE,
                          Event: HANDLE,
                          ApcRoutine: P(IO_APC_ROUTINE),
                          ApcContext: PVOID,
                          IoStatusBlock: P(IO_STATUS_BLOCK),
                          IoControlCode: ULONG,
                          InputBuffer: PVOID,
                          InputBufferLength: ULONG,
                          OutputBuffer: PVOID,
                          OutputBufferLength: ULONG
                          ):
    raise NotImplementedError()

@syscall
def ZwDisableLastKnownGood(dp: Dumpulator
                           ):
    raise NotImplementedError()

@syscall
def ZwDisplayString(dp: Dumpulator,
                    String: P(UNICODE_STRING)
                    ):
    print("debug: " + String.read_unicode_str())
    return STATUS_PRIVILEGE_NOT_HELD

@syscall
def ZwDrawText(dp: Dumpulator,
               Text: P(UNICODE_STRING)
               ):
    raise NotImplementedError()

@syscall
def ZwDuplicateObject(dp: Dumpulator,
                      SourceProcessHandle: HANDLE,
                      SourceHandle: HANDLE,
                      TargetProcessHandle: HANDLE,
                      TargetHandle: P(HANDLE),
                      DesiredAccess: ACCESS_MASK,
                      HandleAttributes: ULONG,
                      Options: ULONG
                      ):
    raise NotImplementedError()

@syscall
def ZwDuplicateToken(dp: Dumpulator,
                     ExistingTokenHandle: HANDLE,
                     DesiredAccess: ACCESS_MASK,
                     ObjectAttributes: P(OBJECT_ATTRIBUTES),
                     EffectiveOnly: BOOLEAN,
                     TokenType: TOKEN_TYPE,
                     NewTokenHandle: P(HANDLE)
                     ):
    raise NotImplementedError()

@syscall
def ZwEnableLastKnownGood(dp: Dumpulator
                          ):
    raise NotImplementedError()

@syscall
def ZwEnumerateBootEntries(dp: Dumpulator,
                           Buffer: PVOID,
                           BufferLength: P(ULONG)
                           ):
    raise NotImplementedError()

@syscall
def ZwEnumerateDriverEntries(dp: Dumpulator,
                             Buffer: PVOID,
                             BufferLength: P(ULONG)
                             ):
    raise NotImplementedError()

@syscall
def ZwEnumerateKey(dp: Dumpulator,
                   KeyHandle: HANDLE,
                   Index: ULONG,
                   KeyInformationClass: KEY_INFORMATION_CLASS,
                   KeyInformation: PVOID,
                   Length: ULONG,
                   ResultLength: P(ULONG)
                   ):
    raise NotImplementedError()

@syscall
def ZwEnumerateSystemEnvironmentValuesEx(dp: Dumpulator,
                                         InformationClass: ULONG,
                                         Buffer: PVOID,
                                         BufferLength: P(ULONG)
                                         ):
    raise NotImplementedError()

@syscall
def ZwEnumerateTransactionObject(dp: Dumpulator,
                                 RootObjectHandle: HANDLE,
                                 QueryType: KTMOBJECT_TYPE,
                                 ObjectCursor: P(KTMOBJECT_CURSOR),
                                 ObjectCursorLength: ULONG,
                                 ReturnLength: P(ULONG)
                                 ):
    raise NotImplementedError()

@syscall
def ZwEnumerateValueKey(dp: Dumpulator,
                        KeyHandle: HANDLE,
                        Index: ULONG,
                        KeyValueInformationClass: KEY_VALUE_INFORMATION_CLASS,
                        KeyValueInformation: PVOID,
                        Length: ULONG,
                        ResultLength: P(ULONG)
                        ):
    raise NotImplementedError()

@syscall
def ZwExtendSection(dp: Dumpulator,
                    SectionHandle: HANDLE,
                    NewSectionSize: P(LARGE_INTEGER)
                    ):
    raise NotImplementedError()

@syscall
def ZwFilterBootOption(dp: Dumpulator,
                       FilterOperation: FILTER_BOOT_OPTION_OPERATION,
                       ObjectType: ULONG,
                       ElementType: ULONG,
                       Data: PVOID,
                       DataSize: ULONG
                       ):
    raise NotImplementedError()

@syscall
def ZwFilterToken(dp: Dumpulator,
                  ExistingTokenHandle: HANDLE,
                  Flags: ULONG,
                  SidsToDisable: P(TOKEN_GROUPS),
                  PrivilegesToDelete: P(TOKEN_PRIVILEGES),
                  RestrictedSids: P(TOKEN_GROUPS),
                  NewTokenHandle: P(HANDLE)
                  ):
    raise NotImplementedError()

@syscall
def ZwFilterTokenEx(dp: Dumpulator,
                    ExistingTokenHandle: HANDLE,
                    Flags: ULONG,
                    SidsToDisable: P(TOKEN_GROUPS),
                    PrivilegesToDelete: P(TOKEN_PRIVILEGES),
                    RestrictedSids: P(TOKEN_GROUPS),
                    DisableUserClaimsCount: ULONG,
                    UserClaimsToDisable: P(UNICODE_STRING),
                    DisableDeviceClaimsCount: ULONG,
                    DeviceClaimsToDisable: P(UNICODE_STRING),
                    DeviceGroupsToDisable: P(TOKEN_GROUPS),
                    RestrictedUserAttributes: P(TOKEN_SECURITY_ATTRIBUTES_INFORMATION),
                    RestrictedDeviceAttributes: P(TOKEN_SECURITY_ATTRIBUTES_INFORMATION),
                    RestrictedDeviceGroups: P(TOKEN_GROUPS),
                    NewTokenHandle: P(HANDLE)
                    ):
    raise NotImplementedError()

@syscall
def ZwFindAtom(dp: Dumpulator,
               AtomName: PWSTR,
               Length: ULONG,
               Atom: P(RTL_ATOM)
               ):
    raise NotImplementedError()

@syscall
def ZwFlushBuffersFile(dp: Dumpulator,
                       FileHandle: HANDLE,
                       IoStatusBlock: P(IO_STATUS_BLOCK)
                       ):
    raise NotImplementedError()

@syscall
def ZwFlushBuffersFileEx(dp: Dumpulator,
                         FileHandle: HANDLE,
                         Flags: ULONG,
                         Parameters: PVOID,
                         ParametersSize: ULONG,
                         IoStatusBlock: P(IO_STATUS_BLOCK)
                         ):
    raise NotImplementedError()

@syscall
def ZwFlushInstallUILanguage(dp: Dumpulator,
                             InstallUILanguage: LANGID,
                             SetComittedFlag: ULONG
                             ):
    raise NotImplementedError()

@syscall
def ZwFlushInstructionCache(dp: Dumpulator,
                            ProcessHandle: HANDLE,
                            BaseAddress: PVOID,
                            Length: SIZE_T
                            ):
    raise NotImplementedError()

@syscall
def ZwFlushKey(dp: Dumpulator,
               KeyHandle: HANDLE
               ):
    raise NotImplementedError()

@syscall
def ZwFlushProcessWriteBuffers(dp: Dumpulator
                               ):
    raise NotImplementedError()

@syscall
def ZwFlushVirtualMemory(dp: Dumpulator,
                         ProcessHandle: HANDLE,
                         BaseAddress: P(PVOID),
                         RegionSize: P(SIZE_T),
                         IoStatus: P(IO_STATUS_BLOCK)
                         ):
    raise NotImplementedError()

@syscall
def ZwFlushWriteBuffer(dp: Dumpulator
                       ):
    raise NotImplementedError()

@syscall
def ZwFreeUserPhysicalPages(dp: Dumpulator,
                            ProcessHandle: HANDLE,
                            NumberOfPages: P(ULONG_PTR),
                            UserPfnArray: P(ULONG_PTR)
                            ):
    raise NotImplementedError()

@syscall
def ZwFreeVirtualMemory(dp: Dumpulator,
                        ProcessHandle: HANDLE,
                        BaseAddress: P(PVOID),
                        RegionSize: P(SIZE_T),
                        FreeType: ULONG
                        ):
    raise NotImplementedError()

@syscall
def ZwFreezeRegistry(dp: Dumpulator,
                     TimeOutInSeconds: ULONG
                     ):
    raise NotImplementedError()

@syscall
def ZwFreezeTransactions(dp: Dumpulator,
                         FreezeTimeout: P(LARGE_INTEGER),
                         ThawTimeout: P(LARGE_INTEGER)
                         ):
    raise NotImplementedError()

@syscall
def ZwFsControlFile(dp: Dumpulator,
                    FileHandle: HANDLE,
                    Event: HANDLE,
                    ApcRoutine: P(IO_APC_ROUTINE),
                    ApcContext: PVOID,
                    IoStatusBlock: P(IO_STATUS_BLOCK),
                    FsControlCode: ULONG,
                    InputBuffer: PVOID,
                    InputBufferLength: ULONG,
                    OutputBuffer: PVOID,
                    OutputBufferLength: ULONG
                    ):
    raise NotImplementedError()

@syscall
def ZwGetCachedSigningLevel(dp: Dumpulator,
                            File: HANDLE,
                            Flags: P(ULONG),
                            SigningLevel: P(SE_SIGNING_LEVEL),
                            Thumbprint: P(UCHAR),
                            ThumbprintSize: P(ULONG),
                            ThumbprintAlgorithm: P(ULONG)
                            ):
    raise NotImplementedError()

@syscall
def ZwGetCompleteWnfStateSubscription(dp: Dumpulator,
                                      OldDescriptorStateName: P(WNF_STATE_NAME),
                                      OldSubscriptionId: P(ULONG64),
                                      OldDescriptorEventMask: ULONG,
                                      OldDescriptorStatus: ULONG,
                                      NewDeliveryDescriptor: P(WNF_DELIVERY_DESCRIPTOR),
                                      DescriptorSize: ULONG
                                      ):
    raise NotImplementedError()

@syscall
def ZwGetContextThread(dp: Dumpulator,
                       ThreadHandle: HANDLE,
                       ThreadContext: P(CONTEXT)
                       ):
    raise NotImplementedError()

@syscall
def ZwGetCurrentProcessorNumber(dp: Dumpulator
                                ):
    raise NotImplementedError()

@syscall
def ZwGetCurrentProcessorNumberEx(dp: Dumpulator,
                                  ProcNumber: P(PROCESSOR_NUMBER)
                                  ):
    raise NotImplementedError()

@syscall
def ZwGetDevicePowerState(dp: Dumpulator,
                          Device: HANDLE,
                          State: P(DEVICE_POWER_STATE)
                          ):
    raise NotImplementedError()

@syscall
def ZwGetMUIRegistryInfo(dp: Dumpulator,
                         Flags: ULONG,
                         DataSize: P(ULONG),
                         Data: PVOID
                         ):
    raise NotImplementedError()

@syscall
def ZwGetNextProcess(dp: Dumpulator,
                     ProcessHandle: HANDLE,
                     DesiredAccess: ACCESS_MASK,
                     HandleAttributes: ULONG,
                     Flags: ULONG,
                     NewProcessHandle: P(HANDLE)
                     ):
    raise NotImplementedError()

@syscall
def ZwGetNextThread(dp: Dumpulator,
                    ProcessHandle: HANDLE,
                    ThreadHandle: HANDLE,
                    DesiredAccess: ACCESS_MASK,
                    HandleAttributes: ULONG,
                    Flags: ULONG,
                    NewThreadHandle: P(HANDLE)
                    ):
    raise NotImplementedError()

@syscall
def ZwGetNlsSectionPtr(dp: Dumpulator,
                       SectionType: ULONG,
                       SectionData: ULONG,
                       ContextData: PVOID,
                       SectionPointer: P(PVOID),
                       SectionSize: P(ULONG)
                       ):
    raise NotImplementedError()

@syscall
def ZwGetNotificationResourceManager(dp: Dumpulator,
                                     ResourceManagerHandle: HANDLE,
                                     TransactionNotification: P(TRANSACTION_NOTIFICATION),
                                     NotificationLength: ULONG,
                                     Timeout: P(LARGE_INTEGER),
                                     ReturnLength: P(ULONG),
                                     Asynchronous: ULONG,
                                     AsynchronousContext: ULONG_PTR
                                     ):
    raise NotImplementedError()

@syscall
def ZwGetPlugPlayEvent(dp: Dumpulator,
                       EventHandle: HANDLE,
                       Context: PVOID,
                       EventBlock: P(PLUGPLAY_EVENT_BLOCK),
                       EventBufferSize: ULONG
                       ):
    raise NotImplementedError()

@syscall
def ZwGetWriteWatch(dp: Dumpulator,
                    ProcessHandle: HANDLE,
                    Flags: ULONG,
                    BaseAddress: PVOID,
                    RegionSize: SIZE_T,
                    UserAddressArray: P(PVOID),
                    EntriesInUserAddressArray: P(ULONG_PTR),
                    Granularity: P(ULONG)
                    ):
    raise NotImplementedError()

@syscall
def ZwImpersonateAnonymousToken(dp: Dumpulator,
                                ThreadHandle: HANDLE
                                ):
    raise NotImplementedError()

@syscall
def ZwImpersonateClientOfPort(dp: Dumpulator,
                              PortHandle: HANDLE,
                              Message: P(PORT_MESSAGE)
                              ):
    raise NotImplementedError()

@syscall
def ZwImpersonateThread(dp: Dumpulator,
                        ServerThreadHandle: HANDLE,
                        ClientThreadHandle: HANDLE,
                        SecurityQos: P(SECURITY_QUALITY_OF_SERVICE)
                        ):
    raise NotImplementedError()

@syscall
def ZwInitializeEnclave(dp: Dumpulator,
                        ProcessHandle: HANDLE,
                        BaseAddress: PVOID,
                        EnclaveInformation: PVOID,
                        EnclaveInformationLength: ULONG,
                        EnclaveError: P(ULONG)
                        ):
    raise NotImplementedError()

@syscall
def ZwInitializeNlsFiles(dp: Dumpulator,
                         BaseAddress: P(PVOID),
                         DefaultLocaleId: P(LCID),
                         DefaultCasingTableSize: P(LARGE_INTEGER)
                         ):
    raise NotImplementedError()

@syscall
def ZwInitializeRegistry(dp: Dumpulator,
                         BootCondition: USHORT
                         ):
    raise NotImplementedError()

@syscall
def ZwInitiatePowerAction(dp: Dumpulator,
                          SystemAction: P(OWER_ACTION),
                          LightestSystemState: SYSTEM_POWER_STATE,
                          Flags: ULONG,
                          Asynchronous: BOOLEAN
                          ):
    raise NotImplementedError()

@syscall
def ZwIsProcessInJob(dp: Dumpulator,
                     ProcessHandle: HANDLE,
                     JobHandle: HANDLE
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
                 PortHandle: HANDLE,
                 ConnectionRequest: P(PORT_MESSAGE)
                 ):
    raise NotImplementedError()

@syscall
def ZwLoadDriver(dp: Dumpulator,
                 DriverServiceName: P(UNICODE_STRING)
                 ):
    raise NotImplementedError()

@syscall
def ZwLoadEnclaveData(dp: Dumpulator,
                      ProcessHandle: HANDLE,
                      BaseAddress: PVOID,
                      Buffer: PVOID,
                      BufferSize: SIZE_T,
                      Protect: ULONG,
                      PageInformation: PVOID,
                      PageInformationLength: ULONG,
                      NumberOfBytesWritten: P(SIZE_T),
                      EnclaveError: P(ULONG)
                      ):
    raise NotImplementedError()

@syscall
def ZwLoadKey(dp: Dumpulator,
              TargetKey: P(OBJECT_ATTRIBUTES),
              SourceFile: P(OBJECT_ATTRIBUTES)
              ):
    raise NotImplementedError()

@syscall
def ZwLoadKey2(dp: Dumpulator,
               TargetKey: P(OBJECT_ATTRIBUTES),
               SourceFile: P(OBJECT_ATTRIBUTES),
               Flags: ULONG
               ):
    raise NotImplementedError()

@syscall
def ZwLoadKeyEx(dp: Dumpulator,
                TargetKey: P(OBJECT_ATTRIBUTES),
                SourceFile: P(OBJECT_ATTRIBUTES),
                Flags: ULONG,
                TrustClassKey: HANDLE,
                Event: HANDLE,
                DesiredAccess: ACCESS_MASK,
                RootHandle: P(HANDLE),
                Reserved: PVOID
                ):
    raise NotImplementedError()

@syscall
def ZwLockFile(dp: Dumpulator,
               FileHandle: HANDLE,
               Event: HANDLE,
               ApcRoutine: P(IO_APC_ROUTINE),
               ApcContext: PVOID,
               IoStatusBlock: P(IO_STATUS_BLOCK),
               ByteOffset: P(LARGE_INTEGER),
               Length: P(LARGE_INTEGER),
               Key: ULONG,
               FailImmediately: BOOLEAN,
               ExclusiveLock: BOOLEAN
               ):
    raise NotImplementedError()

@syscall
def ZwLockProductActivationKeys(dp: Dumpulator,
                                pPrivateVer: P(ULONG),
                                pSafeMode: P(ULONG)
                                ):
    raise NotImplementedError()

@syscall
def ZwLockRegistryKey(dp: Dumpulator,
                      KeyHandle: HANDLE
                      ):
    raise NotImplementedError()

@syscall
def ZwLockVirtualMemory(dp: Dumpulator,
                        ProcessHandle: HANDLE,
                        BaseAddress: P(PVOID),
                        RegionSize: P(SIZE_T),
                        MapType: ULONG
                        ):
    raise NotImplementedError()

@syscall
def ZwMakePermanentObject(dp: Dumpulator,
                          Handle: HANDLE
                          ):
    raise NotImplementedError()

@syscall
def ZwMakeTemporaryObject(dp: Dumpulator,
                          Handle: HANDLE
                          ):
    raise NotImplementedError()

@syscall
def ZwManagePartition(dp: Dumpulator,
                      PartitionInformationClass: MEMORY_PARTITION_INFORMATION_CLASS,
                      PartitionInformation: PVOID,
                      PartitionInformationLength: ULONG
                      ):
    raise NotImplementedError()

@syscall
def ZwMapCMFModule(dp: Dumpulator,
                   What: ULONG,
                   Index: ULONG,
                   CacheIndexOut: P(ULONG),
                   CacheFlagsOut: P(ULONG),
                   ViewSizeOut: P(ULONG),
                   BaseAddress: P(PVOID)
                   ):
    raise NotImplementedError()

@syscall
def ZwMapUserPhysicalPages(dp: Dumpulator,
                           VirtualAddress: PVOID,
                           NumberOfPages: ULONG_PTR,
                           UserPfnArray: P(ULONG_PTR)
                           ):
    raise NotImplementedError()

@syscall
def ZwMapUserPhysicalPagesScatter(dp: Dumpulator,
                                  VirtualAddresses: P(PVOID),
                                  NumberOfPages: ULONG_PTR,
                                  UserPfnArray: P(ULONG_PTR)
                                  ):
    raise NotImplementedError()

@syscall
def ZwMapViewOfSection(dp: Dumpulator,
                       SectionHandle: HANDLE,
                       ProcessHandle: HANDLE,
                       BaseAddress: P(PVOID),
                       ZeroBits: ULONG_PTR,
                       CommitSize: SIZE_T,
                       SectionOffset: P(LARGE_INTEGER),
                       ViewSize: P(SIZE_T),
                       InheritDisposition: SECTION_INHERIT,
                       AllocationType: ULONG,
                       Win32Protect: ULONG
                       ):
    raise NotImplementedError()

@syscall
def ZwModifyBootEntry(dp: Dumpulator,
                      BootEntry: P(BOOT_ENTRY)
                      ):
    raise NotImplementedError()

@syscall
def ZwModifyDriverEntry(dp: Dumpulator,
                        DriverEntry: P(EFI_DRIVER_ENTRY)
                        ):
    raise NotImplementedError()

@syscall
def ZwNotifyChangeDirectoryFile(dp: Dumpulator,
                                FileHandle: HANDLE,
                                Event: HANDLE,
                                ApcRoutine: P(IO_APC_ROUTINE),
                                ApcContext: PVOID,
                                IoStatusBlock: P(IO_STATUS_BLOCK),
                                Buffer: PVOID,
                                Length: ULONG,
                                CompletionFilter: ULONG,
                                WatchTree: BOOLEAN
                                ):
    raise NotImplementedError()

@syscall
def ZwNotifyChangeDirectoryFileEx(dp: Dumpulator,
                                  FileHandle: HANDLE,
                                  Event: HANDLE,
                                  ApcRoutine: P(IO_APC_ROUTINE),
                                  ApcContext: PVOID,
                                  IoStatusBlock: P(IO_STATUS_BLOCK),
                                  Buffer: PVOID,
                                  Length: ULONG,
                                  CompletionFilter: ULONG,
                                  WatchTree: BOOLEAN,
                                  DirectoryNotifyInformationClass: DIRECTORY_NOTIFY_INFORMATION_CLASS
                                  ):
    raise NotImplementedError()

@syscall
def ZwNotifyChangeKey(dp: Dumpulator,
                      KeyHandle: HANDLE,
                      Event: HANDLE,
                      ApcRoutine: P(IO_APC_ROUTINE),
                      ApcContext: PVOID,
                      IoStatusBlock: P(IO_STATUS_BLOCK),
                      CompletionFilter: ULONG,
                      WatchTree: BOOLEAN,
                      Buffer: PVOID,
                      BufferSize: ULONG,
                      Asynchronous: BOOLEAN
                      ):
    raise NotImplementedError()

@syscall
def ZwNotifyChangeMultipleKeys(dp: Dumpulator,
                               MasterKeyHandle: HANDLE,
                               Count: ULONG,
                               SubordinateObjects: P(OBJECT_ATTRIBUTES),
                               Event: HANDLE,
                               ApcRoutine: P(IO_APC_ROUTINE),
                               ApcContext: PVOID,
                               IoStatusBlock: P(IO_STATUS_BLOCK),
                               CompletionFilter: ULONG,
                               WatchTree: BOOLEAN,
                               Buffer: PVOID,
                               BufferSize: ULONG,
                               Asynchronous: BOOLEAN
                               ):
    raise NotImplementedError()

@syscall
def ZwNotifyChangeSession(dp: Dumpulator,
                          SessionHandle: HANDLE,
                          ChangeSequenceNumber: ULONG,
                          ChangeTimeStamp: P(LARGE_INTEGER),
                          Event: IO_SESSION_EVENT,
                          NewState: IO_SESSION_STATE,
                          PreviousState: IO_SESSION_STATE,
                          Payload: PVOID,
                          PayloadSize: ULONG
                          ):
    raise NotImplementedError()

@syscall
def ZwOpenDirectoryObject(dp: Dumpulator,
                          DirectoryHandle: P(HANDLE),
                          DesiredAccess: ACCESS_MASK,
                          ObjectAttributes: P(OBJECT_ATTRIBUTES)
                          ):
    raise NotImplementedError()

@syscall
def ZwOpenEnlistment(dp: Dumpulator,
                     EnlistmentHandle: P(HANDLE),
                     DesiredAccess: ACCESS_MASK,
                     ResourceManagerHandle: HANDLE,
                     EnlistmentGuid: P(GUID),
                     ObjectAttributes: P(OBJECT_ATTRIBUTES)
                     ):
    raise NotImplementedError()

@syscall
def ZwOpenEvent(dp: Dumpulator,
                EventHandle: P(HANDLE),
                DesiredAccess: ACCESS_MASK,
                ObjectAttributes: P(OBJECT_ATTRIBUTES)
                ):
    raise NotImplementedError()

@syscall
def ZwOpenEventPair(dp: Dumpulator,
                    EventPairHandle: P(HANDLE),
                    DesiredAccess: ACCESS_MASK,
                    ObjectAttributes: P(OBJECT_ATTRIBUTES)
                    ):
    raise NotImplementedError()

@syscall
def ZwOpenFile(dp: Dumpulator,
               FileHandle: P(HANDLE),
               DesiredAccess: ACCESS_MASK,
               ObjectAttributes: P(OBJECT_ATTRIBUTES),
               IoStatusBlock: P(IO_STATUS_BLOCK),
               ShareAccess: ULONG,
               OpenOptions: ULONG
               ):
    raise NotImplementedError()

@syscall
def ZwOpenIoCompletion(dp: Dumpulator,
                       IoCompletionHandle: P(HANDLE),
                       DesiredAccess: ACCESS_MASK,
                       ObjectAttributes: P(OBJECT_ATTRIBUTES)
                       ):
    raise NotImplementedError()

@syscall
def ZwOpenJobObject(dp: Dumpulator,
                    JobHandle: P(HANDLE),
                    DesiredAccess: ACCESS_MASK,
                    ObjectAttributes: P(OBJECT_ATTRIBUTES)
                    ):
    raise NotImplementedError()

@syscall
def ZwOpenKey(dp: Dumpulator,
              KeyHandle: P(HANDLE),
              DesiredAccess: ACCESS_MASK,
              ObjectAttributes: P(OBJECT_ATTRIBUTES)
              ):
    raise NotImplementedError()

@syscall
def ZwOpenKeyedEvent(dp: Dumpulator,
                     KeyedEventHandle: P(HANDLE),
                     DesiredAccess: ACCESS_MASK,
                     ObjectAttributes: P(OBJECT_ATTRIBUTES)
                     ):
    raise NotImplementedError()

@syscall
def ZwOpenKeyEx(dp: Dumpulator,
                KeyHandle: P(HANDLE),
                DesiredAccess: ACCESS_MASK,
                ObjectAttributes: P(OBJECT_ATTRIBUTES),
                OpenOptions: ULONG
                ):
    raise NotImplementedError()

@syscall
def ZwOpenKeyTransacted(dp: Dumpulator,
                        KeyHandle: P(HANDLE),
                        DesiredAccess: ACCESS_MASK,
                        ObjectAttributes: P(OBJECT_ATTRIBUTES),
                        TransactionHandle: HANDLE
                        ):
    raise NotImplementedError()

@syscall
def ZwOpenKeyTransactedEx(dp: Dumpulator,
                          KeyHandle: P(HANDLE),
                          DesiredAccess: ACCESS_MASK,
                          ObjectAttributes: P(OBJECT_ATTRIBUTES),
                          OpenOptions: ULONG,
                          TransactionHandle: HANDLE
                          ):
    raise NotImplementedError()

@syscall
def ZwOpenMutant(dp: Dumpulator,
                 MutantHandle: P(HANDLE),
                 DesiredAccess: ACCESS_MASK,
                 ObjectAttributes: P(OBJECT_ATTRIBUTES)
                 ):
    raise NotImplementedError()

@syscall
def ZwOpenObjectAuditAlarm(dp: Dumpulator,
                           SubsystemName: P(UNICODE_STRING),
                           HandleId: PVOID,
                           ObjectTypeName: P(UNICODE_STRING),
                           ObjectName: P(UNICODE_STRING),
                           SecurityDescriptor: P(SECURITY_DESCRIPTOR),
                           ClientToken: HANDLE,
                           DesiredAccess: ACCESS_MASK,
                           GrantedAccess: ACCESS_MASK,
                           Privileges: P(PRIVILEGE_SET),
                           ObjectCreation: BOOLEAN,
                           AccessGranted: BOOLEAN,
                           GenerateOnClose: P(BOOLEAN)
                           ):
    raise NotImplementedError()

@syscall
def ZwOpenPartition(dp: Dumpulator,
                    PartitionHandle: P(HANDLE),
                    DesiredAccess: ACCESS_MASK,
                    ObjectAttributes: P(OBJECT_ATTRIBUTES)
                    ):
    raise NotImplementedError()

@syscall
def ZwOpenPrivateNamespace(dp: Dumpulator,
                           NamespaceHandle: P(HANDLE),
                           DesiredAccess: ACCESS_MASK,
                           ObjectAttributes: P(OBJECT_ATTRIBUTES),
                           BoundaryDescriptor: PVOID
                           ):
    raise NotImplementedError()

@syscall
def ZwOpenProcess(dp: Dumpulator,
                  ProcessHandle: P(HANDLE),
                  DesiredAccess: ACCESS_MASK,
                  ObjectAttributes: P(OBJECT_ATTRIBUTES),
                  ClientId: P(CLIENT_ID)
                  ):
    raise NotImplementedError()

@syscall
def ZwOpenProcessToken(dp: Dumpulator,
                       ProcessHandle: HANDLE,
                       DesiredAccess: ACCESS_MASK,
                       TokenHandle: P(HANDLE)
                       ):
    raise NotImplementedError()

@syscall
def ZwOpenProcessTokenEx(dp: Dumpulator,
                         ProcessHandle: HANDLE,
                         DesiredAccess: ACCESS_MASK,
                         HandleAttributes: ULONG,
                         TokenHandle: P(HANDLE)
                         ):
    raise NotImplementedError()

@syscall
def ZwOpenResourceManager(dp: Dumpulator,
                          ResourceManagerHandle: P(HANDLE),
                          DesiredAccess: ACCESS_MASK,
                          TmHandle: HANDLE,
                          ResourceManagerGuid: P(GUID),
                          ObjectAttributes: P(OBJECT_ATTRIBUTES)
                          ):
    raise NotImplementedError()

@syscall
def ZwOpenSection(dp: Dumpulator,
                  SectionHandle: P(HANDLE),
                  DesiredAccess: ACCESS_MASK,
                  ObjectAttributes: P(OBJECT_ATTRIBUTES)
                  ):
    raise NotImplementedError()

@syscall
def ZwOpenSemaphore(dp: Dumpulator,
                    SemaphoreHandle: P(HANDLE),
                    DesiredAccess: ACCESS_MASK,
                    ObjectAttributes: P(OBJECT_ATTRIBUTES)
                    ):
    raise NotImplementedError()

@syscall
def ZwOpenSession(dp: Dumpulator,
                  SessionHandle: P(HANDLE),
                  DesiredAccess: ACCESS_MASK,
                  ObjectAttributes: P(OBJECT_ATTRIBUTES)
                  ):
    raise NotImplementedError()

@syscall
def ZwOpenSymbolicLinkObject(dp: Dumpulator,
                             LinkHandle: P(HANDLE),
                             DesiredAccess: ACCESS_MASK,
                             ObjectAttributes: P(OBJECT_ATTRIBUTES)
                             ):
    raise NotImplementedError()

@syscall
def ZwOpenThread(dp: Dumpulator,
                 ThreadHandle: P(HANDLE),
                 DesiredAccess: ACCESS_MASK,
                 ObjectAttributes: P(OBJECT_ATTRIBUTES),
                 ClientId: P(CLIENT_ID)
                 ):
    raise NotImplementedError()

@syscall
def ZwOpenThreadToken(dp: Dumpulator,
                      ThreadHandle: HANDLE,
                      DesiredAccess: ACCESS_MASK,
                      OpenAsSelf: BOOLEAN,
                      TokenHandle: P(HANDLE)
                      ):
    raise NotImplementedError()

@syscall
def ZwOpenThreadTokenEx(dp: Dumpulator,
                        ThreadHandle: HANDLE,
                        DesiredAccess: ACCESS_MASK,
                        OpenAsSelf: BOOLEAN,
                        HandleAttributes: ULONG,
                        TokenHandle: P(HANDLE)
                        ):
    raise NotImplementedError()

@syscall
def ZwOpenTimer(dp: Dumpulator,
                TimerHandle: P(HANDLE),
                DesiredAccess: ACCESS_MASK,
                ObjectAttributes: P(OBJECT_ATTRIBUTES)
                ):
    raise NotImplementedError()

@syscall
def ZwOpenTransaction(dp: Dumpulator,
                      TransactionHandle: P(HANDLE),
                      DesiredAccess: ACCESS_MASK,
                      ObjectAttributes: P(OBJECT_ATTRIBUTES),
                      Uow: P(GUID),
                      TmHandle: HANDLE
                      ):
    raise NotImplementedError()

@syscall
def ZwOpenTransactionManager(dp: Dumpulator,
                             TmHandle: P(HANDLE),
                             DesiredAccess: ACCESS_MASK,
                             ObjectAttributes: P(OBJECT_ATTRIBUTES),
                             LogFileName: P(UNICODE_STRING),
                             TmIdentity: P(GUID),
                             OpenOptions: ULONG
                             ):
    raise NotImplementedError()

@syscall
def ZwPlugPlayControl(dp: Dumpulator,
                      PnPControlClass: PLUGPLAY_CONTROL_CLASS,
                      PnPControlData: PVOID,
                      PnPControlDataLength: ULONG
                      ):
    raise NotImplementedError()

@syscall
def ZwPowerInformation(dp: Dumpulator,
                       InformationLevel: P(OWER_INFORMATION_LEVEL),
                       InputBuffer: PVOID,
                       InputBufferLength: ULONG,
                       OutputBuffer: PVOID,
                       OutputBufferLength: ULONG
                       ):
    raise NotImplementedError()

@syscall
def ZwPrepareComplete(dp: Dumpulator,
                      EnlistmentHandle: HANDLE,
                      TmVirtualClock: P(LARGE_INTEGER)
                      ):
    raise NotImplementedError()

@syscall
def ZwPrepareEnlistment(dp: Dumpulator,
                        EnlistmentHandle: HANDLE,
                        TmVirtualClock: P(LARGE_INTEGER)
                        ):
    raise NotImplementedError()

@syscall
def ZwPrePrepareComplete(dp: Dumpulator,
                         EnlistmentHandle: HANDLE,
                         TmVirtualClock: P(LARGE_INTEGER)
                         ):
    raise NotImplementedError()

@syscall
def ZwPrePrepareEnlistment(dp: Dumpulator,
                           EnlistmentHandle: HANDLE,
                           TmVirtualClock: P(LARGE_INTEGER)
                           ):
    raise NotImplementedError()

@syscall
def ZwPrivilegeCheck(dp: Dumpulator,
                     ClientToken: HANDLE,
                     RequiredPrivileges: P(PRIVILEGE_SET),
                     Result: P(BOOLEAN)
                     ):
    raise NotImplementedError()

@syscall
def ZwPrivilegedServiceAuditAlarm(dp: Dumpulator,
                                  SubsystemName: P(UNICODE_STRING),
                                  ServiceName: P(UNICODE_STRING),
                                  ClientToken: HANDLE,
                                  Privileges: P(PRIVILEGE_SET),
                                  AccessGranted: BOOLEAN
                                  ):
    raise NotImplementedError()

@syscall
def ZwPrivilegeObjectAuditAlarm(dp: Dumpulator,
                                SubsystemName: P(UNICODE_STRING),
                                HandleId: PVOID,
                                ClientToken: HANDLE,
                                DesiredAccess: ACCESS_MASK,
                                Privileges: P(PRIVILEGE_SET),
                                AccessGranted: BOOLEAN
                                ):
    raise NotImplementedError()

@syscall
def ZwPropagationComplete(dp: Dumpulator,
                          ResourceManagerHandle: HANDLE,
                          RequestCookie: ULONG,
                          BufferLength: ULONG,
                          Buffer: PVOID
                          ):
    raise NotImplementedError()

@syscall
def ZwPropagationFailed(dp: Dumpulator,
                        ResourceManagerHandle: HANDLE,
                        RequestCookie: ULONG,
                        PropStatus: NTSTATUS
                        ):
    raise NotImplementedError()

@syscall
def ZwProtectVirtualMemory(dp: Dumpulator,
                           ProcessHandle: HANDLE,
                           BaseAddress: P(PVOID),
                           RegionSize: P(SIZE_T),
                           NewProtect: ULONG,
                           OldProtect: P(ULONG)
                           ):
    base = BaseAddress[0] & 0xFFFFFFFFFFFFF000
    size = round_to_pages(RegionSize[0])

    print(f"protect {base:x}[{size:x}] = {NewProtect:x}")
    dp.protect(base, size, NewProtect)
    # TODO: OldProtect is not implemented
    return STATUS_SUCCESS

@syscall
def ZwPulseEvent(dp: Dumpulator,
                 EventHandle: HANDLE,
                 PreviousState: P(LONG)
                 ):
    raise NotImplementedError()

@syscall
def ZwQueryAttributesFile(dp: Dumpulator,
                          ObjectAttributes: P(OBJECT_ATTRIBUTES),
                          FileInformation: P(FILE_BASIC_INFORMATION)
                          ):
    raise NotImplementedError()

@syscall
def ZwQueryBootEntryOrder(dp: Dumpulator,
                          Ids: P(ULONG),
                          Count: P(ULONG)
                          ):
    raise NotImplementedError()

@syscall
def ZwQueryBootOptions(dp: Dumpulator,
                       BootOptions: P(BOOT_OPTIONS),
                       BootOptionsLength: P(ULONG)
                       ):
    raise NotImplementedError()

@syscall
def ZwQueryDebugFilterState(dp: Dumpulator,
                            ComponentId: ULONG,
                            Level: ULONG
                            ):
    raise NotImplementedError()

@syscall
def ZwQueryDefaultLocale(dp: Dumpulator,
                         UserProfile: BOOLEAN,
                         DefaultLocaleId: P(LCID)
                         ):
    raise NotImplementedError()

@syscall
def ZwQueryDefaultUILanguage(dp: Dumpulator,
                             DefaultUILanguageId: P(LANGID)
                             ):
    raise NotImplementedError()

@syscall
def ZwQueryDirectoryFile(dp: Dumpulator,
                         FileHandle: HANDLE,
                         Event: HANDLE,
                         ApcRoutine: P(IO_APC_ROUTINE),
                         ApcContext: PVOID,
                         IoStatusBlock: P(IO_STATUS_BLOCK),
                         FileInformation: PVOID,
                         Length: ULONG,
                         FileInformationClass: FILE_INFORMATION_CLASS,
                         ReturnSingleEntry: BOOLEAN,
                         FileName: P(UNICODE_STRING),
                         RestartScan: BOOLEAN
                         ):
    raise NotImplementedError()

@syscall
def ZwQueryDirectoryFileEx(dp: Dumpulator,
                           FileHandle: HANDLE,
                           Event: HANDLE,
                           ApcRoutine: P(IO_APC_ROUTINE),
                           ApcContext: PVOID,
                           IoStatusBlock: P(IO_STATUS_BLOCK),
                           FileInformation: PVOID,
                           Length: ULONG,
                           FileInformationClass: FILE_INFORMATION_CLASS,
                           QueryFlags: ULONG,
                           FileName: P(UNICODE_STRING)
                           ):
    raise NotImplementedError()

@syscall
def ZwQueryDirectoryObject(dp: Dumpulator,
                           DirectoryHandle: HANDLE,
                           Buffer: PVOID,
                           Length: ULONG,
                           ReturnSingleEntry: BOOLEAN,
                           RestartScan: BOOLEAN,
                           Context: P(ULONG),
                           ReturnLength: P(ULONG)
                           ):
    raise NotImplementedError()

@syscall
def ZwQueryDriverEntryOrder(dp: Dumpulator,
                            Ids: P(ULONG),
                            Count: P(ULONG)
                            ):
    raise NotImplementedError()

@syscall
def ZwQueryEaFile(dp: Dumpulator,
                  FileHandle: HANDLE,
                  IoStatusBlock: P(IO_STATUS_BLOCK),
                  Buffer: PVOID,
                  Length: ULONG,
                  ReturnSingleEntry: BOOLEAN,
                  EaList: PVOID,
                  EaListLength: ULONG,
                  EaIndex: P(ULONG),
                  RestartScan: BOOLEAN
                  ):
    raise NotImplementedError()

@syscall
def ZwQueryEvent(dp: Dumpulator,
                 EventHandle: HANDLE,
                 EventInformationClass: EVENT_INFORMATION_CLASS,
                 EventInformation: PVOID,
                 EventInformationLength: ULONG,
                 ReturnLength: P(ULONG)
                 ):
    raise NotImplementedError()

@syscall
def ZwQueryFullAttributesFile(dp: Dumpulator,
                              ObjectAttributes: P(OBJECT_ATTRIBUTES),
                              FileInformation: P(FILE_NETWORK_OPEN_INFORMATION)
                              ):
    raise NotImplementedError()

@syscall
def ZwQueryInformationAtom(dp: Dumpulator,
                           Atom: RTL_ATOM,
                           AtomInformationClass: ATOM_INFORMATION_CLASS,
                           AtomInformation: PVOID,
                           AtomInformationLength: ULONG,
                           ReturnLength: P(ULONG)
                           ):
    raise NotImplementedError()

@syscall
def ZwQueryInformationByName(dp: Dumpulator,
                             ObjectAttributes: P(OBJECT_ATTRIBUTES),
                             IoStatusBlock: P(IO_STATUS_BLOCK),
                             FileInformation: PVOID,
                             Length: ULONG,
                             FileInformationClass: FILE_INFORMATION_CLASS
                             ):
    raise NotImplementedError()

@syscall
def ZwQueryInformationEnlistment(dp: Dumpulator,
                                 EnlistmentHandle: HANDLE,
                                 EnlistmentInformationClass: ENLISTMENT_INFORMATION_CLASS,
                                 EnlistmentInformation: PVOID,
                                 EnlistmentInformationLength: ULONG,
                                 ReturnLength: P(ULONG)
                                 ):
    raise NotImplementedError()

@syscall
def ZwQueryInformationFile(dp: Dumpulator,
                           FileHandle: HANDLE,
                           IoStatusBlock: P(IO_STATUS_BLOCK),
                           FileInformation: PVOID,
                           Length: ULONG,
                           FileInformationClass: FILE_INFORMATION_CLASS
                           ):
    raise NotImplementedError()

@syscall
def ZwQueryInformationJobObject(dp: Dumpulator,
                                JobHandle: HANDLE,
                                JobObjectInformationClass: JOBOBJECTINFOCLASS,
                                JobObjectInformation: PVOID,
                                JobObjectInformationLength: ULONG,
                                ReturnLength: P(ULONG)
                                ):
    raise NotImplementedError()

@syscall
def ZwQueryInformationPort(dp: Dumpulator,
                           PortHandle: HANDLE,
                           PortInformationClass: PORT_INFORMATION_CLASS,
                           PortInformation: PVOID,
                           Length: ULONG,
                           ReturnLength: P(ULONG)
                           ):
    raise NotImplementedError()

@syscall
def ZwQueryInformationProcess(dp: Dumpulator,
                              ProcessHandle: HANDLE,
                              ProcessInformationClass: PROCESSINFOCLASS,
                              ProcessInformation: PVOID,
                              ProcessInformationLength: ULONG,
                              ReturnLength: P(ULONG)
                              ):
    assert (ProcessHandle == dp.NtCurrentProcess())
    if ProcessInformationClass in [PROCESSINFOCLASS.ProcessDebugPort, PROCESSINFOCLASS.ProcessDebugObjectHandle]:
        assert (ProcessInformationLength == 4)
        dp.write_ulong(ProcessInformation.ptr, 0)
        if ReturnLength != 0:
            dp.write_ulong(ReturnLength.ptr, 4)
        return STATUS_SUCCESS
    raise NotImplementedError()

@syscall
def ZwQueryInformationResourceManager(dp: Dumpulator,
                                      ResourceManagerHandle: HANDLE,
                                      ResourceManagerInformationClass: RESOURCEMANAGER_INFORMATION_CLASS,
                                      ResourceManagerInformation: PVOID,
                                      ResourceManagerInformationLength: ULONG,
                                      ReturnLength: P(ULONG)
                                      ):
    raise NotImplementedError()

@syscall
def ZwQueryInformationThread(dp: Dumpulator,
                             ThreadHandle: HANDLE,
                             ThreadInformationClass: THREADINFOCLASS,
                             ThreadInformation: PVOID,
                             ThreadInformationLength: ULONG,
                             ReturnLength: P(ULONG)
                             ):
    if ThreadInformationClass == THREADINFOCLASS.ThreadDynamicCodePolicyInfo:
        assert ThreadInformationLength == 4
        assert ReturnLength == 0
        dp.write_ulong(ThreadInformation, 0)
        return STATUS_SUCCESS
    raise Exception()

@syscall
def ZwQueryInformationToken(dp: Dumpulator,
                            TokenHandle: HANDLE,
                            TokenInformationClass: TOKEN_INFORMATION_CLASS,
                            TokenInformation: PVOID,
                            TokenInformationLength: ULONG,
                            ReturnLength: P(ULONG)
                            ):
    raise NotImplementedError()

@syscall
def ZwQueryInformationTransaction(dp: Dumpulator,
                                  TransactionHandle: HANDLE,
                                  TransactionInformationClass: TRANSACTION_INFORMATION_CLASS,
                                  TransactionInformation: PVOID,
                                  TransactionInformationLength: ULONG,
                                  ReturnLength: P(ULONG)
                                  ):
    raise NotImplementedError()

@syscall
def ZwQueryInformationTransactionManager(dp: Dumpulator,
                                         TransactionManagerHandle: HANDLE,
                                         TransactionManagerInformationClass: TRANSACTIONMANAGER_INFORMATION_CLASS,
                                         TransactionManagerInformation: PVOID,
                                         TransactionManagerInformationLength: ULONG,
                                         ReturnLength: P(ULONG)
                                         ):
    raise NotImplementedError()

@syscall
def ZwQueryInformationWorkerFactory(dp: Dumpulator,
                                    WorkerFactoryHandle: HANDLE,
                                    WorkerFactoryInformationClass: WORKERFACTORYINFOCLASS,
                                    WorkerFactoryInformation: PVOID,
                                    WorkerFactoryInformationLength: ULONG,
                                    ReturnLength: P(ULONG)
                                    ):
    raise NotImplementedError()

@syscall
def ZwQueryInstallUILanguage(dp: Dumpulator,
                             InstallUILanguageId: P(LANGID)
                             ):
    raise NotImplementedError()

@syscall
def ZwQueryIntervalProfile(dp: Dumpulator,
                           ProfileSource: KPROFILE_SOURCE,
                           Interval: P(ULONG)
                           ):
    raise NotImplementedError()

@syscall
def ZwQueryIoCompletion(dp: Dumpulator,
                        IoCompletionHandle: HANDLE,
                        IoCompletionInformationClass: IO_COMPLETION_INFORMATION_CLASS,
                        IoCompletionInformation: PVOID,
                        IoCompletionInformationLength: ULONG,
                        ReturnLength: P(ULONG)
                        ):
    raise NotImplementedError()

@syscall
def ZwQueryKey(dp: Dumpulator,
               KeyHandle: HANDLE,
               KeyInformationClass: KEY_INFORMATION_CLASS,
               KeyInformation: PVOID,
               Length: ULONG,
               ResultLength: P(ULONG)
               ):
    raise NotImplementedError()

@syscall
def ZwQueryLicenseValue(dp: Dumpulator,
                        ValueName: P(UNICODE_STRING),
                        Type: P(ULONG),
                        Data: PVOID,
                        DataSize: ULONG,
                        ResultDataSize: P(ULONG)
                        ):
    raise NotImplementedError()

@syscall
def ZwQueryMultipleValueKey(dp: Dumpulator,
                            KeyHandle: HANDLE,
                            ValueEntries: P(KEY_VALUE_ENTRY),
                            EntryCount: ULONG,
                            ValueBuffer: PVOID,
                            BufferLength: P(ULONG),
                            RequiredBufferLength: P(ULONG)
                            ):
    raise NotImplementedError()

@syscall
def ZwQueryMutant(dp: Dumpulator,
                  MutantHandle: HANDLE,
                  MutantInformationClass: MUTANT_INFORMATION_CLASS,
                  MutantInformation: PVOID,
                  MutantInformationLength: ULONG,
                  ReturnLength: P(ULONG)
                  ):
    raise NotImplementedError()

@syscall
def ZwQueryObject(dp: Dumpulator,
                  Handle: HANDLE,
                  ObjectInformationClass: OBJECT_INFORMATION_CLASS,
                  ObjectInformation: PVOID,
                  ObjectInformationLength: ULONG,
                  ReturnLength: P(ULONG)
                  ):
    raise NotImplementedError()

@syscall
def ZwQueryOpenSubKeys(dp: Dumpulator,
                       TargetKey: P(OBJECT_ATTRIBUTES),
                       HandleCount: P(ULONG)
                       ):
    raise NotImplementedError()

@syscall
def ZwQueryOpenSubKeysEx(dp: Dumpulator,
                         TargetKey: P(OBJECT_ATTRIBUTES),
                         BufferLength: ULONG,
                         Buffer: PVOID,
                         RequiredSize: P(ULONG)
                         ):
    raise NotImplementedError()

@syscall
def ZwQueryPerformanceCounter(dp: Dumpulator,
                              PerformanceCounter: P(LARGE_INTEGER),
                              PerformanceFrequency: P(LARGE_INTEGER)
                              ):
    raise NotImplementedError()

@syscall
def ZwQueryPortInformationProcess(dp: Dumpulator
                                  ):
    raise NotImplementedError()

@syscall
def ZwQueryQuotaInformationFile(dp: Dumpulator,
                                FileHandle: HANDLE,
                                IoStatusBlock: P(IO_STATUS_BLOCK),
                                Buffer: PVOID,
                                Length: ULONG,
                                ReturnSingleEntry: BOOLEAN,
                                SidList: PVOID,
                                SidListLength: ULONG,
                                StartSid: PSID,
                                RestartScan: BOOLEAN
                                ):
    raise NotImplementedError()

@syscall
def ZwQuerySection(dp: Dumpulator,
                   SectionHandle: HANDLE,
                   SectionInformationClass: SECTION_INFORMATION_CLASS,
                   SectionInformation: PVOID,
                   SectionInformationLength: SIZE_T,
                   ReturnLength: P(SIZE_T)
                   ):
    raise NotImplementedError()

@syscall
def ZwQuerySecurityAttributesToken(dp: Dumpulator,
                                   TokenHandle: HANDLE,
                                   Attributes: P(UNICODE_STRING),
                                   NumberOfAttributes: ULONG,
                                   Buffer: PVOID,
                                   Length: ULONG,
                                   ReturnLength: P(ULONG)
                                   ):
    raise NotImplementedError()

@syscall
def ZwQuerySecurityObject(dp: Dumpulator,
                          Handle: HANDLE,
                          SecurityInformation: SECURITY_INFORMATION,
                          SecurityDescriptor: P(SECURITY_DESCRIPTOR),
                          Length: ULONG,
                          LengthNeeded: P(ULONG)
                          ):
    raise NotImplementedError()

@syscall
def ZwQuerySemaphore(dp: Dumpulator,
                     SemaphoreHandle: HANDLE,
                     SemaphoreInformationClass: SEMAPHORE_INFORMATION_CLASS,
                     SemaphoreInformation: PVOID,
                     SemaphoreInformationLength: ULONG,
                     ReturnLength: P(ULONG)
                     ):
    raise NotImplementedError()

@syscall
def ZwQuerySymbolicLinkObject(dp: Dumpulator,
                              LinkHandle: HANDLE,
                              LinkTarget: P(UNICODE_STRING),
                              ReturnedLength: P(ULONG)
                              ):
    raise NotImplementedError()

@syscall
def ZwQuerySystemEnvironmentValue(dp: Dumpulator,
                                  VariableName: P(UNICODE_STRING),
                                  VariableValue: PWSTR,
                                  ValueLength: USHORT,
                                  ReturnLength: P(USHORT)
                                  ):
    raise NotImplementedError()

@syscall
def ZwQuerySystemEnvironmentValueEx(dp: Dumpulator,
                                    VariableName: P(UNICODE_STRING),
                                    VendorGuid: P(GUID),
                                    Value: PVOID,
                                    ValueLength: P(ULONG),
                                    Attributes: P(ULONG)
                                    ):
    raise NotImplementedError()

@syscall
def ZwQuerySystemInformation(dp: Dumpulator,
                             SystemInformationClass: SYSTEM_INFORMATION_CLASS,
                             SystemInformation: PVOID,
                             SystemInformationLength: ULONG,
                             ReturnLength: P(ULONG)
                             ):
    raise NotImplementedError()

@syscall
def ZwQuerySystemInformationEx(dp: Dumpulator,
                               SystemInformationClass: SYSTEM_INFORMATION_CLASS,
                               InputBuffer: PVOID,
                               InputBufferLength: ULONG,
                               SystemInformation: PVOID,
                               SystemInformationLength: ULONG,
                               ReturnLength: P(ULONG)
                               ):
    raise NotImplementedError()

@syscall
def ZwQuerySystemTime(dp: Dumpulator,
                      SystemTime: P(LARGE_INTEGER)
                      ):
    raise NotImplementedError()

@syscall
def ZwQueryTimer(dp: Dumpulator,
                 TimerHandle: HANDLE,
                 TimerInformationClass: TIMER_INFORMATION_CLASS,
                 TimerInformation: PVOID,
                 TimerInformationLength: ULONG,
                 ReturnLength: P(ULONG)
                 ):
    raise NotImplementedError()

@syscall
def ZwQueryTimerResolution(dp: Dumpulator,
                           MaximumTime: P(ULONG),
                           MinimumTime: P(ULONG),
                           CurrentTime: P(ULONG)
                           ):
    raise NotImplementedError()

@syscall
def ZwQueryValueKey(dp: Dumpulator,
                    KeyHandle: HANDLE,
                    ValueName: P(UNICODE_STRING),
                    KeyValueInformationClass: KEY_VALUE_INFORMATION_CLASS,
                    KeyValueInformation: PVOID,
                    Length: ULONG,
                    ResultLength: P(ULONG)
                    ):
    raise NotImplementedError()

@syscall
def ZwQueryVirtualMemory(dp: Dumpulator,
                         ProcessHandle: HANDLE,
                         BaseAddress: PVOID,
                         MemoryInformationClass: MEMORY_INFORMATION_CLASS,
                         MemoryInformation: PVOID,
                         MemoryInformationLength: SIZE_T,
                         ReturnLength: P(SIZE_T)
                         ):
    raise NotImplementedError()

@syscall
def ZwQueryVolumeInformationFile(dp: Dumpulator,
                                 FileHandle: HANDLE,
                                 IoStatusBlock: P(IO_STATUS_BLOCK),
                                 FsInformation: PVOID,
                                 Length: ULONG,
                                 FsInformationClass: FSINFOCLASS
                                 ):
    raise NotImplementedError()

@syscall
def ZwQueryWnfStateData(dp: Dumpulator,
                        StateName: P(CWNF_STATE_NAME),
                        TypeId: P(CWNF_TYPE_ID),
                        ExplicitScope: PVOID,
                        ChangeStamp: P(WNF_CHANGE_STAMP),
                        Buffer: PVOID,
                        BufferSize: P(ULONG)
                        ):
    raise NotImplementedError()

@syscall
def ZwQueryWnfStateNameInformation(dp: Dumpulator,
                                   StateName: P(CWNF_STATE_NAME),
                                   NameInfoClass: WNF_STATE_NAME_INFORMATION,
                                   ExplicitScope: PVOID,
                                   InfoBuffer: PVOID,
                                   InfoBufferSize: ULONG
                                   ):
    raise NotImplementedError()

@syscall
def ZwQueueApcThread(dp: Dumpulator,
                     ThreadHandle: HANDLE,
                     ApcRoutine: P(PS_APC_ROUTINE),
                     ApcArgument1: PVOID,
                     ApcArgument2: PVOID,
                     ApcArgument3: PVOID
                     ):
    raise NotImplementedError()

@syscall
def ZwQueueApcThreadEx(dp: Dumpulator,
                       ThreadHandle: HANDLE,
                       ReserveHandle: HANDLE,
                       ApcRoutine: P(PS_APC_ROUTINE),
                       ApcArgument1: PVOID,
                       ApcArgument2: PVOID,
                       ApcArgument3: PVOID
                       ):
    raise NotImplementedError()

@syscall
def ZwRaiseException(dp: Dumpulator,
                     ExceptionRecord: P(EXCEPTION_RECORD),
                     ContextRecord: P(CONTEXT),
                     FirstChance: BOOLEAN
                     ):
    raise NotImplementedError()

@syscall
def ZwRaiseHardError(dp: Dumpulator,
                     ErrorStatus: NTSTATUS,
                     NumberOfParameters: ULONG,
                     UnicodeStringParameterMask: ULONG,
                     Parameters: P(ULONG_PTR),
                     ValidResponseOptions: ULONG,
                     Response: P(ULONG)
                     ):
    raise NotImplementedError()

@syscall
def ZwReadFile(dp: Dumpulator,
               FileHandle: HANDLE,
               Event: HANDLE,
               ApcRoutine: P(IO_APC_ROUTINE),
               ApcContext: PVOID,
               IoStatusBlock: P(IO_STATUS_BLOCK),
               Buffer: PVOID,
               Length: ULONG,
               ByteOffset: P(LARGE_INTEGER),
               Key: P(ULONG)
               ):
    raise NotImplementedError()

@syscall
def ZwReadFileScatter(dp: Dumpulator,
                      FileHandle: HANDLE,
                      Event: HANDLE,
                      ApcRoutine: P(IO_APC_ROUTINE),
                      ApcContext: PVOID,
                      IoStatusBlock: P(IO_STATUS_BLOCK),
                      SegmentArray: P(FILE_SEGMENT_ELEMENT),
                      Length: ULONG,
                      ByteOffset: P(LARGE_INTEGER),
                      Key: P(ULONG)
                      ):
    raise NotImplementedError()

@syscall
def ZwReadOnlyEnlistment(dp: Dumpulator,
                         EnlistmentHandle: HANDLE,
                         TmVirtualClock: P(LARGE_INTEGER)
                         ):
    raise NotImplementedError()

@syscall
def ZwReadRequestData(dp: Dumpulator,
                      PortHandle: HANDLE,
                      Message: P(PORT_MESSAGE),
                      DataEntryIndex: ULONG,
                      Buffer: PVOID,
                      BufferSize: SIZE_T,
                      NumberOfBytesRead: P(SIZE_T)
                      ):
    raise NotImplementedError()

@syscall
def ZwReadVirtualMemory(dp: Dumpulator,
                        ProcessHandle: HANDLE,
                        BaseAddress: PVOID,
                        Buffer: PVOID,
                        BufferSize: SIZE_T,
                        NumberOfBytesRead: P(SIZE_T)
                        ):
    raise NotImplementedError()

@syscall
def ZwRecoverEnlistment(dp: Dumpulator,
                        EnlistmentHandle: HANDLE,
                        EnlistmentKey: PVOID
                        ):
    raise NotImplementedError()

@syscall
def ZwRecoverResourceManager(dp: Dumpulator,
                             ResourceManagerHandle: HANDLE
                             ):
    raise NotImplementedError()

@syscall
def ZwRecoverTransactionManager(dp: Dumpulator,
                                TransactionManagerHandle: HANDLE
                                ):
    raise NotImplementedError()

@syscall
def ZwRegisterProtocolAddressInformation(dp: Dumpulator,
                                         ResourceManager: HANDLE,
                                         ProtocolId: P(CRM_PROTOCOL_ID),
                                         ProtocolInformationSize: ULONG,
                                         ProtocolInformation: PVOID,
                                         CreateOptions: ULONG
                                         ):
    raise NotImplementedError()

@syscall
def ZwRegisterThreadTerminatePort(dp: Dumpulator,
                                  PortHandle: HANDLE
                                  ):
    raise NotImplementedError()

@syscall
def ZwReleaseCMFViewOwnership(dp: Dumpulator
                              ):
    raise NotImplementedError()

@syscall
def ZwReleaseKeyedEvent(dp: Dumpulator,
                        KeyedEventHandle: HANDLE,
                        KeyValue: PVOID,
                        Alertable: BOOLEAN,
                        Timeout: P(LARGE_INTEGER)
                        ):
    raise NotImplementedError()

@syscall
def ZwReleaseMutant(dp: Dumpulator,
                    MutantHandle: HANDLE,
                    PreviousCount: P(LONG)
                    ):
    raise NotImplementedError()

@syscall
def ZwReleaseSemaphore(dp: Dumpulator,
                       SemaphoreHandle: HANDLE,
                       ReleaseCount: LONG,
                       PreviousCount: P(LONG)
                       ):
    raise NotImplementedError()

@syscall
def ZwReleaseWorkerFactoryWorker(dp: Dumpulator,
                                 WorkerFactoryHandle: HANDLE
                                 ):
    raise NotImplementedError()

@syscall
def ZwRemoveIoCompletion(dp: Dumpulator,
                         IoCompletionHandle: HANDLE,
                         KeyContext: P(PVOID),
                         ApcContext: P(PVOID),
                         IoStatusBlock: P(IO_STATUS_BLOCK),
                         Timeout: P(LARGE_INTEGER)
                         ):
    raise NotImplementedError()

@syscall
def ZwRemoveIoCompletionEx(dp: Dumpulator,
                           IoCompletionHandle: HANDLE,
                           IoCompletionInformation: P(FILE_IO_COMPLETION_INFORMATION),
                           Count: ULONG,
                           NumEntriesRemoved: P(ULONG),
                           Timeout: P(LARGE_INTEGER),
                           Alertable: BOOLEAN
                           ):
    raise NotImplementedError()

@syscall
def ZwRemoveProcessDebug(dp: Dumpulator,
                         ProcessHandle: HANDLE,
                         DebugObjectHandle: HANDLE
                         ):
    raise NotImplementedError()

@syscall
def ZwRenameKey(dp: Dumpulator,
                KeyHandle: HANDLE,
                NewName: P(UNICODE_STRING)
                ):
    raise NotImplementedError()

@syscall
def ZwRenameTransactionManager(dp: Dumpulator,
                               LogFileName: P(UNICODE_STRING),
                               ExistingTransactionManagerGuid: P(GUID)
                               ):
    raise NotImplementedError()

@syscall
def ZwReplaceKey(dp: Dumpulator,
                 NewFile: P(OBJECT_ATTRIBUTES),
                 TargetHandle: HANDLE,
                 OldFile: P(OBJECT_ATTRIBUTES)
                 ):
    raise NotImplementedError()

@syscall
def ZwReplacePartitionUnit(dp: Dumpulator,
                           TargetInstancePath: P(UNICODE_STRING),
                           SpareInstancePath: P(UNICODE_STRING),
                           Flags: ULONG
                           ):
    raise NotImplementedError()

@syscall
def ZwReplyPort(dp: Dumpulator,
                PortHandle: HANDLE,
                ReplyMessage: P(PORT_MESSAGE)
                ):
    raise NotImplementedError()

@syscall
def ZwReplyWaitReceivePort(dp: Dumpulator,
                           PortHandle: HANDLE,
                           PortContext: P(PVOID),
                           ReplyMessage: P(PORT_MESSAGE),
                           ReceiveMessage: P(PORT_MESSAGE)
                           ):
    raise NotImplementedError()

@syscall
def ZwReplyWaitReceivePortEx(dp: Dumpulator,
                             PortHandle: HANDLE,
                             PortContext: P(PVOID),
                             ReplyMessage: P(PORT_MESSAGE),
                             ReceiveMessage: P(PORT_MESSAGE),
                             Timeout: P(LARGE_INTEGER)
                             ):
    raise NotImplementedError()

@syscall
def ZwReplyWaitReplyPort(dp: Dumpulator,
                         PortHandle: HANDLE,
                         ReplyMessage: P(PORT_MESSAGE)
                         ):
    raise NotImplementedError()

@syscall
def ZwRequestPort(dp: Dumpulator,
                  PortHandle: HANDLE,
                  RequestMessage: P(PORT_MESSAGE)
                  ):
    raise NotImplementedError()

@syscall
def ZwRequestWaitReplyPort(dp: Dumpulator,
                           PortHandle: HANDLE,
                           RequestMessage: P(PORT_MESSAGE),
                           ReplyMessage: P(PORT_MESSAGE)
                           ):
    raise NotImplementedError()

@syscall
def ZwRequestWakeupLatency(dp: Dumpulator,
                           latency: LATENCY_TIME
                           ):
    raise NotImplementedError()

@syscall
def ZwResetEvent(dp: Dumpulator,
                 EventHandle: HANDLE,
                 PreviousState: P(LONG)
                 ):
    raise NotImplementedError()

@syscall
def ZwResetWriteWatch(dp: Dumpulator,
                      ProcessHandle: HANDLE,
                      BaseAddress: PVOID,
                      RegionSize: SIZE_T
                      ):
    raise NotImplementedError()

@syscall
def ZwRestoreKey(dp: Dumpulator,
                 KeyHandle: HANDLE,
                 FileHandle: HANDLE,
                 Flags: ULONG
                 ):
    raise NotImplementedError()

@syscall
def ZwResumeProcess(dp: Dumpulator,
                    ProcessHandle: HANDLE
                    ):
    raise NotImplementedError()

@syscall
def ZwResumeThread(dp: Dumpulator,
                   ThreadHandle: HANDLE,
                   PreviousSuspendCount: P(ULONG)
                   ):
    raise NotImplementedError()

@syscall
def ZwRevertContainerImpersonation(dp: Dumpulator
                                   ):
    raise NotImplementedError()

@syscall
def ZwRollbackComplete(dp: Dumpulator,
                       EnlistmentHandle: HANDLE,
                       TmVirtualClock: P(LARGE_INTEGER)
                       ):
    raise NotImplementedError()

@syscall
def ZwRollbackEnlistment(dp: Dumpulator,
                         EnlistmentHandle: HANDLE,
                         TmVirtualClock: P(LARGE_INTEGER)
                         ):
    raise NotImplementedError()

@syscall
def ZwRollbackTransaction(dp: Dumpulator,
                          TransactionHandle: HANDLE,
                          Wait: BOOLEAN
                          ):
    raise NotImplementedError()

@syscall
def ZwRollforwardTransactionManager(dp: Dumpulator,
                                    TransactionManagerHandle: HANDLE,
                                    TmVirtualClock: P(LARGE_INTEGER)
                                    ):
    raise NotImplementedError()

@syscall
def ZwSaveKey(dp: Dumpulator,
              KeyHandle: HANDLE,
              FileHandle: HANDLE
              ):
    raise NotImplementedError()

@syscall
def ZwSaveKeyEx(dp: Dumpulator,
                KeyHandle: HANDLE,
                FileHandle: HANDLE,
                Format: ULONG
                ):
    raise NotImplementedError()

@syscall
def ZwSaveMergedKeys(dp: Dumpulator,
                     HighPrecedenceKeyHandle: HANDLE,
                     LowPrecedenceKeyHandle: HANDLE,
                     FileHandle: HANDLE
                     ):
    raise NotImplementedError()

@syscall
def ZwSecureConnectPort(dp: Dumpulator,
                        PortHandle: P(HANDLE),
                        PortName: P(UNICODE_STRING),
                        SecurityQos: P(SECURITY_QUALITY_OF_SERVICE),
                        ClientView: P(PORT_VIEW),
                        RequiredServerSid: PSID,
                        ServerView: P(REMOTE_PORT_VIEW),
                        MaxMessageLength: P(ULONG),
                        ConnectionInformation: PVOID,
                        ConnectionInformationLength: P(ULONG)
                        ):
    raise NotImplementedError()

@syscall
def ZwSerializeBoot(dp: Dumpulator
                    ):
    raise NotImplementedError()

@syscall
def ZwSetBootEntryOrder(dp: Dumpulator,
                        Ids: P(ULONG),
                        Count: ULONG
                        ):
    raise NotImplementedError()

@syscall
def ZwSetBootOptions(dp: Dumpulator,
                     BootOptions: P(BOOT_OPTIONS),
                     FieldsToChange: ULONG
                     ):
    raise NotImplementedError()

@syscall
def ZwSetCachedSigningLevel(dp: Dumpulator,
                            Flags: ULONG,
                            InputSigningLevel: SE_SIGNING_LEVEL,
                            SourceFiles: P(HANDLE),
                            SourceFileCount: ULONG,
                            TargetFile: HANDLE
                            ):
    raise NotImplementedError()

@syscall
def ZwSetContextThread(dp: Dumpulator,
                       ThreadHandle: HANDLE,
                       ThreadContext: P(CONTEXT)
                       ):
    raise NotImplementedError()

@syscall
def ZwSetDebugFilterState(dp: Dumpulator,
                          ComponentId: ULONG,
                          Level: ULONG,
                          State: BOOLEAN
                          ):
    raise NotImplementedError()

@syscall
def ZwSetDefaultHardErrorPort(dp: Dumpulator,
                              DefaultHardErrorPort: HANDLE
                              ):
    raise NotImplementedError()

@syscall
def ZwSetDefaultLocale(dp: Dumpulator,
                       UserProfile: BOOLEAN,
                       DefaultLocaleId: LCID
                       ):
    raise NotImplementedError()

@syscall
def ZwSetDefaultUILanguage(dp: Dumpulator,
                           DefaultUILanguageId: LANGID
                           ):
    raise NotImplementedError()

@syscall
def ZwSetDriverEntryOrder(dp: Dumpulator,
                          Ids: P(ULONG),
                          Count: ULONG
                          ):
    raise NotImplementedError()

@syscall
def ZwSetEaFile(dp: Dumpulator,
                FileHandle: HANDLE,
                IoStatusBlock: P(IO_STATUS_BLOCK),
                Buffer: PVOID,
                Length: ULONG
                ):
    raise NotImplementedError()

@syscall
def ZwSetEvent(dp: Dumpulator,
               EventHandle: HANDLE,
               PreviousState: P(LONG)
               ):
    raise NotImplementedError()

@syscall
def ZwSetEventBoostPriority(dp: Dumpulator,
                            EventHandle: HANDLE
                            ):
    raise NotImplementedError()

@syscall
def ZwSetHighEventPair(dp: Dumpulator,
                       EventPairHandle: HANDLE
                       ):
    raise NotImplementedError()

@syscall
def ZwSetHighWaitLowEventPair(dp: Dumpulator,
                              EventPairHandle: HANDLE
                              ):
    raise NotImplementedError()

@syscall
def ZwSetInformationDebugObject(dp: Dumpulator,
                                DebugObjectHandle: HANDLE,
                                DebugObjectInformationClass: DEBUGOBJECTINFOCLASS,
                                DebugInformation: PVOID,
                                DebugInformationLength: ULONG,
                                ReturnLength: P(ULONG)
                                ):
    raise NotImplementedError()

@syscall
def ZwSetInformationEnlistment(dp: Dumpulator,
                               EnlistmentHandle: HANDLE,
                               EnlistmentInformationClass: ENLISTMENT_INFORMATION_CLASS,
                               EnlistmentInformation: PVOID,
                               EnlistmentInformationLength: ULONG
                               ):
    raise NotImplementedError()

@syscall
def ZwSetInformationFile(dp: Dumpulator,
                         FileHandle: HANDLE,
                         IoStatusBlock: P(IO_STATUS_BLOCK),
                         FileInformation: PVOID,
                         Length: ULONG,
                         FileInformationClass: FILE_INFORMATION_CLASS
                         ):
    raise NotImplementedError()

@syscall
def ZwSetInformationJobObject(dp: Dumpulator,
                              JobHandle: HANDLE,
                              JobObjectInformationClass: JOBOBJECTINFOCLASS,
                              JobObjectInformation: PVOID,
                              JobObjectInformationLength: ULONG
                              ):
    raise NotImplementedError()

@syscall
def ZwSetInformationKey(dp: Dumpulator,
                        KeyHandle: HANDLE,
                        KeySetInformationClass: KEY_SET_INFORMATION_CLASS,
                        KeySetInformation: PVOID,
                        KeySetInformationLength: ULONG
                        ):
    raise NotImplementedError()

@syscall
def ZwSetInformationObject(dp: Dumpulator,
                           Handle: HANDLE,
                           ObjectInformationClass: OBJECT_INFORMATION_CLASS,
                           ObjectInformation: PVOID,
                           ObjectInformationLength: ULONG
                           ):
    raise NotImplementedError()

@syscall
def ZwSetInformationProcess(dp: Dumpulator,
                            ProcessHandle: HANDLE,
                            ProcessInformationClass: PROCESSINFOCLASS,
                            ProcessInformation: PVOID,
                            ProcessInformationLength: ULONG
                            ):
    raise NotImplementedError()

@syscall
def ZwSetInformationResourceManager(dp: Dumpulator,
                                    ResourceManagerHandle: HANDLE,
                                    ResourceManagerInformationClass: RESOURCEMANAGER_INFORMATION_CLASS,
                                    ResourceManagerInformation: PVOID,
                                    ResourceManagerInformationLength: ULONG
                                    ):
    raise NotImplementedError()

@syscall
def ZwSetInformationSymbolicLink(dp: Dumpulator,
                                 LinkHandle: HANDLE,
                                 SymbolicLinkInformationClass: SYMBOLIC_LINK_INFO_CLASS,
                                 SymbolicLinkInformation: PVOID,
                                 SymbolicLinkInformationLength: ULONG
                                 ):
    raise NotImplementedError()

@syscall
def ZwSetInformationThread(dp: Dumpulator,
                           ThreadHandle: HANDLE,
                           ThreadInformationClass: THREADINFOCLASS,
                           ThreadInformation: PVOID,
                           ThreadInformationLength: ULONG
                           ):
    if ThreadInformationClass == THREADINFOCLASS.ThreadHideFromDebugger:
        assert ThreadInformation == 0
        assert ThreadInformationLength == 0
        assert ThreadHandle == dp.NtCurrentThread()
        return STATUS_SUCCESS
    raise NotImplementedError()

@syscall
def ZwSetInformationToken(dp: Dumpulator,
                          TokenHandle: HANDLE,
                          TokenInformationClass: TOKEN_INFORMATION_CLASS,
                          TokenInformation: PVOID,
                          TokenInformationLength: ULONG
                          ):
    raise NotImplementedError()

@syscall
def ZwSetInformationTransaction(dp: Dumpulator,
                                TransactionHandle: HANDLE,
                                TransactionInformationClass: TRANSACTION_INFORMATION_CLASS,
                                TransactionInformation: PVOID,
                                TransactionInformationLength: ULONG
                                ):
    raise NotImplementedError()

@syscall
def ZwSetInformationTransactionManager(dp: Dumpulator,
                                       TmHandle: HANDLE,
                                       TransactionManagerInformationClass: TRANSACTIONMANAGER_INFORMATION_CLASS,
                                       TransactionManagerInformation: PVOID,
                                       TransactionManagerInformationLength: ULONG
                                       ):
    raise NotImplementedError()

@syscall
def ZwSetInformationVirtualMemory(dp: Dumpulator,
                                  ProcessHandle: HANDLE,
                                  VmInformationClass: VIRTUAL_MEMORY_INFORMATION_CLASS,
                                  NumberOfEntries: ULONG_PTR,
                                  VirtualAddresses: P(MEMORY_RANGE_ENTRY),
                                  VmInformation: PVOID,
                                  VmInformationLength: ULONG
                                  ):
    raise NotImplementedError()

@syscall
def ZwSetInformationWorkerFactory(dp: Dumpulator,
                                  WorkerFactoryHandle: HANDLE,
                                  WorkerFactoryInformationClass: WORKERFACTORYINFOCLASS,
                                  WorkerFactoryInformation: PVOID,
                                  WorkerFactoryInformationLength: ULONG
                                  ):
    raise NotImplementedError()

@syscall
def ZwSetIntervalProfile(dp: Dumpulator,
                         Interval: ULONG,
                         Source: KPROFILE_SOURCE
                         ):
    raise NotImplementedError()

@syscall
def ZwSetIoCompletion(dp: Dumpulator,
                      IoCompletionHandle: HANDLE,
                      KeyContext: PVOID,
                      ApcContext: PVOID,
                      IoStatus: NTSTATUS,
                      IoStatusInformation: ULONG_PTR
                      ):
    raise NotImplementedError()

@syscall
def ZwSetIoCompletionEx(dp: Dumpulator,
                        IoCompletionHandle: HANDLE,
                        IoCompletionPacketHandle: HANDLE,
                        KeyContext: PVOID,
                        ApcContext: PVOID,
                        IoStatus: NTSTATUS,
                        IoStatusInformation: ULONG_PTR
                        ):
    raise NotImplementedError()

@syscall
def ZwSetIRTimer(dp: Dumpulator,
                 TimerHandle: HANDLE,
                 DueTime: P(LARGE_INTEGER)
                 ):
    raise NotImplementedError()

@syscall
def ZwSetLdtEntries(dp: Dumpulator,
                    Selector0: ULONG,
                    Entry0Low: ULONG,
                    Entry0Hi: ULONG,
                    Selector1: ULONG,
                    Entry1Low: ULONG,
                    Entry1Hi: ULONG
                    ):
    raise NotImplementedError()

@syscall
def ZwSetLowEventPair(dp: Dumpulator,
                      EventPairHandle: HANDLE
                      ):
    raise NotImplementedError()

@syscall
def ZwSetLowWaitHighEventPair(dp: Dumpulator,
                              EventPairHandle: HANDLE
                              ):
    raise NotImplementedError()

@syscall
def ZwSetQuotaInformationFile(dp: Dumpulator,
                              FileHandle: HANDLE,
                              IoStatusBlock: P(IO_STATUS_BLOCK),
                              Buffer: PVOID,
                              Length: ULONG
                              ):
    raise NotImplementedError()

@syscall
def ZwSetSecurityObject(dp: Dumpulator,
                        Handle: HANDLE,
                        SecurityInformation: SECURITY_INFORMATION,
                        SecurityDescriptor: P(SECURITY_DESCRIPTOR)
                        ):
    raise NotImplementedError()

@syscall
def ZwSetSystemEnvironmentValue(dp: Dumpulator,
                                VariableName: P(UNICODE_STRING),
                                VariableValue: P(UNICODE_STRING)
                                ):
    raise NotImplementedError()

@syscall
def ZwSetSystemEnvironmentValueEx(dp: Dumpulator,
                                  VariableName: P(UNICODE_STRING),
                                  VendorGuid: P(GUID),
                                  Value: PVOID,
                                  ValueLength: ULONG,
                                  Attributes: ULONG
                                  ):
    raise NotImplementedError()

@syscall
def ZwSetSystemInformation(dp: Dumpulator,
                           SystemInformationClass: SYSTEM_INFORMATION_CLASS,
                           SystemInformation: PVOID,
                           SystemInformationLength: ULONG
                           ):
    raise NotImplementedError()

@syscall
def ZwSetSystemPowerState(dp: Dumpulator,
                          SystemAction: P(OWER_ACTION),
                          LightestSystemState: SYSTEM_POWER_STATE,
                          Flags: ULONG
                          ):
    raise NotImplementedError()

@syscall
def ZwSetSystemTime(dp: Dumpulator,
                    SystemTime: P(LARGE_INTEGER),
                    PreviousTime: P(LARGE_INTEGER)
                    ):
    raise NotImplementedError()

@syscall
def ZwSetThreadExecutionState(dp: Dumpulator,
                              NewFlags: EXECUTION_STATE,
                              PreviousFlags: P(EXECUTION_STATE)
                              ):
    raise NotImplementedError()

@syscall
def ZwSetTimer(dp: Dumpulator,
               TimerHandle: HANDLE,
               DueTime: P(LARGE_INTEGER),
               TimerApcRoutine: P(TIMER_APC_ROUTINE),
               TimerContext: PVOID,
               ResumeTimer: BOOLEAN,
               Period: LONG,
               PreviousState: P(BOOLEAN)
               ):
    raise NotImplementedError()

@syscall
def ZwSetTimer2(dp: Dumpulator,
                TimerHandle: HANDLE,
                DueTime: P(LARGE_INTEGER),
                Period: P(LARGE_INTEGER),
                Parameters: P(T2_SET_PARAMETERS)
                ):
    raise NotImplementedError()

@syscall
def ZwSetTimerEx(dp: Dumpulator,
                 TimerHandle: HANDLE,
                 TimerSetInformationClass: TIMER_SET_INFORMATION_CLASS,
                 TimerSetInformation: PVOID,
                 TimerSetInformationLength: ULONG
                 ):
    raise NotImplementedError()

@syscall
def ZwSetTimerResolution(dp: Dumpulator,
                         DesiredTime: ULONG,
                         SetResolution: BOOLEAN,
                         ActualTime: P(ULONG)
                         ):
    raise NotImplementedError()

@syscall
def ZwSetUuidSeed(dp: Dumpulator,
                  Seed: P(CHAR)
                  ):
    raise NotImplementedError()

@syscall
def ZwSetValueKey(dp: Dumpulator,
                  KeyHandle: HANDLE,
                  ValueName: P(UNICODE_STRING),
                  TitleIndex: ULONG,
                  Type: ULONG,
                  Data: PVOID,
                  DataSize: ULONG
                  ):
    raise NotImplementedError()

@syscall
def ZwSetVolumeInformationFile(dp: Dumpulator,
                               FileHandle: HANDLE,
                               IoStatusBlock: P(IO_STATUS_BLOCK),
                               FsInformation: PVOID,
                               Length: ULONG,
                               FsInformationClass: FSINFOCLASS
                               ):
    raise NotImplementedError()

@syscall
def ZwSetWnfProcessNotificationEvent(dp: Dumpulator,
                                     NotificationEvent: HANDLE
                                     ):
    raise NotImplementedError()

@syscall
def ZwShutdownSystem(dp: Dumpulator,
                     Action: SHUTDOWN_ACTION
                     ):
    raise NotImplementedError()

@syscall
def ZwShutdownWorkerFactory(dp: Dumpulator,
                            WorkerFactoryHandle: HANDLE,
                            PendingWorkerCount: P(LONG)
                            ):
    raise NotImplementedError()

@syscall
def ZwSignalAndWaitForSingleObject(dp: Dumpulator,
                                   SignalHandle: HANDLE,
                                   WaitHandle: HANDLE,
                                   Alertable: BOOLEAN,
                                   Timeout: P(LARGE_INTEGER)
                                   ):
    raise NotImplementedError()

@syscall
def ZwSinglePhaseReject(dp: Dumpulator,
                        EnlistmentHandle: HANDLE,
                        TmVirtualClock: P(LARGE_INTEGER)
                        ):
    raise NotImplementedError()

@syscall
def ZwStartProfile(dp: Dumpulator,
                   ProfileHandle: HANDLE
                   ):
    raise NotImplementedError()

@syscall
def ZwStopProfile(dp: Dumpulator,
                  ProfileHandle: HANDLE
                  ):
    raise NotImplementedError()

@syscall
def ZwSubscribeWnfStateChange(dp: Dumpulator,
                              StateName: P(CWNF_STATE_NAME),
                              ChangeStamp: WNF_CHANGE_STAMP,
                              EventMask: ULONG,
                              SubscriptionId: P(ULONG64)
                              ):
    raise NotImplementedError()

@syscall
def ZwSuspendProcess(dp: Dumpulator,
                     ProcessHandle: HANDLE
                     ):
    raise NotImplementedError()

@syscall
def ZwSuspendThread(dp: Dumpulator,
                    ThreadHandle: HANDLE,
                    PreviousSuspendCount: P(ULONG)
                    ):
    raise NotImplementedError()

@syscall
def ZwSystemDebugControl(dp: Dumpulator,
                         Command: SYSDBG_COMMAND,
                         InputBuffer: PVOID,
                         InputBufferLength: ULONG,
                         OutputBuffer: PVOID,
                         OutputBufferLength: ULONG,
                         ReturnLength: P(ULONG)
                         ):
    raise NotImplementedError()

@syscall
def ZwTerminateEnclave(dp: Dumpulator,
                       BaseAddress: PVOID,
                       WaitForThread: BOOLEAN
                       ):
    raise NotImplementedError()

@syscall
def ZwTerminateJobObject(dp: Dumpulator,
                         JobHandle: HANDLE,
                         ExitStatus: NTSTATUS
                         ):
    raise NotImplementedError()

@syscall
def ZwTerminateProcess(dp: Dumpulator,
                       ProcessHandle: HANDLE,
                       ExitStatus: NTSTATUS
                       ):
    assert ProcessHandle == 0 or ProcessHandle == dp.NtCurrentProcess()
    dp.stop(ExitStatus)
    return STATUS_SUCCESS

@syscall
def ZwTerminateThread(dp: Dumpulator,
                      ThreadHandle: HANDLE,
                      ExitStatus: NTSTATUS
                      ):
    assert ThreadHandle == dp.NtCurrentThread()
    return STATUS_NOT_IMPLEMENTED

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
                   TraceInformationClass: TRACE_CONTROL_INFORMATION_CLASS,
                   InputBuffer: PVOID,
                   InputBufferLength: ULONG,
                   TraceInformation: PVOID,
                   TraceInformationLength: ULONG,
                   ReturnLength: P(ULONG)
                   ):
    raise NotImplementedError()

@syscall
def ZwTraceEvent(dp: Dumpulator,
                 TraceHandle: HANDLE,
                 Flags: ULONG,
                 FieldSize: ULONG,
                 Fields: PVOID
                 ):
    raise NotImplementedError()

@syscall
def ZwTranslateFilePath(dp: Dumpulator,
                        InputFilePath: P(FILE_PATH),
                        OutputType: ULONG,
                        OutputFilePath: P(FILE_PATH),
                        OutputFilePathLength: P(ULONG)
                        ):
    raise NotImplementedError()

@syscall
def ZwUmsThreadYield(dp: Dumpulator,
                     SchedulerParam: PVOID
                     ):
    raise NotImplementedError()

@syscall
def ZwUnloadDriver(dp: Dumpulator,
                   DriverServiceName: P(UNICODE_STRING)
                   ):
    raise NotImplementedError()

@syscall
def ZwUnloadKey(dp: Dumpulator,
                TargetKey: P(OBJECT_ATTRIBUTES)
                ):
    raise NotImplementedError()

@syscall
def ZwUnloadKey2(dp: Dumpulator,
                 TargetKey: P(OBJECT_ATTRIBUTES),
                 Flags: ULONG
                 ):
    raise NotImplementedError()

@syscall
def ZwUnloadKeyEx(dp: Dumpulator,
                  TargetKey: P(OBJECT_ATTRIBUTES),
                  Event: HANDLE
                  ):
    raise NotImplementedError()

@syscall
def ZwUnlockFile(dp: Dumpulator,
                 FileHandle: HANDLE,
                 IoStatusBlock: P(IO_STATUS_BLOCK),
                 ByteOffset: P(LARGE_INTEGER),
                 Length: P(LARGE_INTEGER),
                 Key: ULONG
                 ):
    raise NotImplementedError()

@syscall
def ZwUnlockVirtualMemory(dp: Dumpulator,
                          ProcessHandle: HANDLE,
                          BaseAddress: P(PVOID),
                          RegionSize: P(SIZE_T),
                          MapType: ULONG
                          ):
    raise NotImplementedError()

@syscall
def ZwUnmapViewOfSection(dp: Dumpulator,
                         ProcessHandle: HANDLE,
                         BaseAddress: PVOID
                         ):
    raise NotImplementedError()

@syscall
def ZwUnmapViewOfSectionEx(dp: Dumpulator,
                           ProcessHandle: HANDLE,
                           BaseAddress: PVOID,
                           Flags: ULONG
                           ):
    raise NotImplementedError()

@syscall
def ZwUnsubscribeWnfStateChange(dp: Dumpulator,
                                StateName: P(CWNF_STATE_NAME)
                                ):
    raise NotImplementedError()

@syscall
def ZwUpdateWnfStateData(dp: Dumpulator,
                         StateName: P(CWNF_STATE_NAME),
                         Buffer: PVOID,
                         Length: ULONG,
                         TypeId: P(CWNF_TYPE_ID),
                         ExplicitScope: PVOID,
                         MatchingChangeStamp: WNF_CHANGE_STAMP,
                         CheckStamp: LOGICAL
                         ):
    raise NotImplementedError()

@syscall
def ZwVdmControl(dp: Dumpulator,
                 Service: VDMSERVICECLASS,
                 ServiceData: PVOID
                 ):
    raise NotImplementedError()

@syscall
def ZwWaitForAlertByThreadId(dp: Dumpulator,
                             Address: PVOID,
                             Timeout: P(LARGE_INTEGER)
                             ):
    raise NotImplementedError()

@syscall
def ZwWaitForDebugEvent(dp: Dumpulator,
                        DebugObjectHandle: HANDLE,
                        Alertable: BOOLEAN,
                        Timeout: P(LARGE_INTEGER),
                        WaitStateChange: P(DBGUI_WAIT_STATE_CHANGE)
                        ):
    raise NotImplementedError()

@syscall
def ZwWaitForKeyedEvent(dp: Dumpulator,
                        KeyedEventHandle: HANDLE,
                        KeyValue: PVOID,
                        Alertable: BOOLEAN,
                        Timeout: P(LARGE_INTEGER)
                        ):
    raise NotImplementedError()

@syscall
def ZwWaitForMultipleObjects(dp: Dumpulator,
                             Count: ULONG,
                             Handles: P(HANDLE),
                             WaitType: WAIT_TYPE,
                             Alertable: BOOLEAN,
                             Timeout: P(LARGE_INTEGER)
                             ):
    raise NotImplementedError()

@syscall
def ZwWaitForMultipleObjects32(dp: Dumpulator,
                               Count: ULONG,
                               Handles: P(LONG),
                               WaitType: WAIT_TYPE,
                               Alertable: BOOLEAN,
                               Timeout: P(LARGE_INTEGER)
                               ):
    raise NotImplementedError()

@syscall
def ZwWaitForSingleObject(dp: Dumpulator,
                          Handle: HANDLE,
                          Alertable: BOOLEAN,
                          Timeout: P(LARGE_INTEGER)
                          ):
    raise NotImplementedError()

@syscall
def ZwWaitForWorkViaWorkerFactory(dp: Dumpulator,
                                  WorkerFactoryHandle: HANDLE,
                                  MiniPacket: P(FILE_IO_COMPLETION_INFORMATION)
                                  ):
    raise NotImplementedError()

@syscall
def ZwWaitHighEventPair(dp: Dumpulator,
                        EventPairHandle: HANDLE
                        ):
    raise NotImplementedError()

@syscall
def ZwWaitLowEventPair(dp: Dumpulator,
                       EventPairHandle: HANDLE
                       ):
    raise NotImplementedError()

@syscall
def ZwWorkerFactoryWorkerReady(dp: Dumpulator,
                               WorkerFactoryHandle: HANDLE
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
                FileHandle: HANDLE,
                Event: HANDLE,
                ApcRoutine: P(IO_APC_ROUTINE),
                ApcContext: PVOID,
                IoStatusBlock: P(IO_STATUS_BLOCK),
                Buffer: PVOID,
                Length: ULONG,
                ByteOffset: P(LARGE_INTEGER),
                Key: P(ULONG)
                ):
    data = Buffer.read_str(Length)
    print(data)
    return STATUS_SUCCESS

@syscall
def ZwWriteFileGather(dp: Dumpulator,
                      FileHandle: HANDLE,
                      Event: HANDLE,
                      ApcRoutine: P(IO_APC_ROUTINE),
                      ApcContext: PVOID,
                      IoStatusBlock: P(IO_STATUS_BLOCK),
                      SegmentArray: P(FILE_SEGMENT_ELEMENT),
                      Length: ULONG,
                      ByteOffset: P(LARGE_INTEGER),
                      Key: P(ULONG)
                      ):
    raise NotImplementedError()

@syscall
def ZwWriteRequestData(dp: Dumpulator,
                       PortHandle: HANDLE,
                       Message: P(PORT_MESSAGE),
                       DataEntryIndex: ULONG,
                       Buffer: PVOID,
                       BufferSize: SIZE_T,
                       NumberOfBytesWritten: P(SIZE_T)
                       ):
    raise NotImplementedError()

@syscall
def ZwWriteVirtualMemory(dp: Dumpulator,
                         ProcessHandle: HANDLE,
                         BaseAddress: PVOID,
                         Buffer: PVOID,
                         BufferSize: SIZE_T,
                         NumberOfBytesWritten: P(SIZE_T)
                         ):
    raise NotImplementedError()

@syscall
def ZwYieldExecution(dp: Dumpulator
                     ):
    raise NotImplementedError()

