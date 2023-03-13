from .ntprimitives import *

class IO_STATUS_BLOCK(Struct):
    Pointer: PVOID
    Information: ULONG_PTR

    @staticmethod
    def write(ptr: PVOID, Status: int, Information: int):
        # https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_status_block
        pointer_data = ptr.read_ptr()
        pointer_data &= 0xFFFFFFFF00000000
        pointer_data |= Status
        ptr.write_ptr(pointer_data)
        ptr.arch.write_ptr(ptr.ptr + ptr.arch.ptr_size(), Information)

class UNICODE_STRING(Struct):
    Length: USHORT
    MaximumLength: USHORT
    Buffer: P[USHORT]

    def read_str(self):
        return self.Buffer.read(self.Length).decode("utf-16")

    @staticmethod
    def create_buffer(s: str, ptr: PVOID) -> bytes:
        encoded = s.encode("utf-16-le") + b"\0\0"
        if ptr.arch.x64:
            data = struct.pack("<HHIQ", len(encoded) - 2, len(encoded), 0, int(ptr) + 16)
        else:
            data = struct.pack("<HHI", len(encoded) - 2, len(encoded), int(ptr) + 8)
        return data + encoded

class SECURITY_DESCRIPTOR:
    pass

class SECURITY_QUALITY_OF_SERVICE:
    pass

class OBJECT_ATTRIBUTES(Struct):
    Length: ULONG
    RootDirectory: HANDLE
    ObjectName: P[UNICODE_STRING]
    Attributes: ULONG
    SecurityDescriptor: P[SECURITY_DESCRIPTOR]
    SecurityQualityOfService: P[SECURITY_QUALITY_OF_SERVICE]

class ALPC_CONTEXT_ATTR:
    pass

class ALPC_DATA_VIEW_ATTR:
    pass

class ALPC_MESSAGE_ATTRIBUTES:
    pass

class ALPC_PORT_ATTRIBUTES:
    pass

class ALPC_SECURITY_ATTR:
    pass

class BOOT_ENTRY:
    pass

class BOOT_OPTIONS:
    pass

class CLIENT_ID:
    pass

class CRM_PROTOCOL_ID:
    pass

class CWNF_STATE_NAME:
    pass

class CWNF_TYPE_ID:
    pass

class DBGUI_WAIT_STATE_CHANGE:
    pass

class EFI_DRIVER_ENTRY:
    pass

class ENCLAVE_ROUTINE:
    pass

class EXCEPTION_RECORD:
    pass

class FILE_BASIC_INFORMATION:
    pass

class FILE_IO_COMPLETION_INFORMATION:
    pass

class FILE_NETWORK_OPEN_INFORMATION:
    pass

class FILE_PATH:
    pass

class FILE_SEGMENT_ELEMENT:
    pass

class GENERIC_MAPPING:
    pass

class GROUP_AFFINITY:
    pass

class GUID:
    pass

class INITIAL_TEB:
    pass

class IO_APC_ROUTINE:
    pass

class JOB_SET_ARRAY:
    pass

class KEY_LOAD_ENTRY:
    pass

class KEY_VALUE_ENTRY:
    pass

class KTMOBJECT_CURSOR:
    pass

class LARGE_INTEGER:
    pass

class LUID:
    pass

class MEMORY_RANGE_ENTRY:
    pass

class MEM_EXTENDED_PARAMETER:
    pass

class OBJECT_BOUNDARY_DESCRIPTOR:
    pass

class OBJECT_TYPE_LIST:
    pass

class OWER_ACTION:
    pass

class OWER_INFORMATION_LEVEL:
    pass

class PLUGPLAY_EVENT_BLOCK:
    pass

class PORT_MESSAGE:
    pass

class PORT_VIEW:
    pass

class PRIVILEGE_SET:
    pass

class PROCESSOR_NUMBER:
    pass

class PS_APC_ROUTINE:
    pass

class PS_ATTRIBUTE_LIST:
    pass

class PS_CREATE_INFO:
    pass

class REMOTE_PORT_VIEW:
    pass

class SID_AND_ATTRIBUTES:
    pass

class T2_CANCEL_PARAMETERS:
    pass

class T2_SET_PARAMETERS:
    pass

class TIMER_APC_ROUTINE:
    pass

class TOKEN_DEFAULT_DACL:
    pass

class TOKEN_GROUPS:
    pass

class TOKEN_MANDATORY_POLICY:
    pass

class TOKEN_OWNER:
    pass

class TOKEN_PRIMARY_GROUP:
    pass

class TOKEN_PRIVILEGES:
    pass

class TOKEN_SECURITY_ATTRIBUTES_INFORMATION:
    pass

class TOKEN_SOURCE:
    pass

class TOKEN_USER:
    pass

class TRANSACTION_NOTIFICATION:
    pass

class ULARGE_INTEGER:
    pass

class WNF_DELIVERY_DESCRIPTOR:
    pass

class WNF_STATE_NAME:
    pass

class WORKER_FACTORY_DEFERRED_WORK:
    pass
