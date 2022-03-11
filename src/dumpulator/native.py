import struct
from typing import Optional
from .ntenums import *
from .ntprimitives import *
from .ntstructs import *

STATUS_SUCCESS = 0
STATUS_NOT_IMPLEMENTED = 0xC0000002
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_PRIVILEGE_NOT_HELD = 0xC0000061

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x4

# Temporary manual definitions

class IO_APC_ROUTINE:
    pass

class IO_STATUS_BLOCK:
    pass

class LARGE_INTEGER:
    pass

class UNICODE_STRING:
    pass

def round_to_pages(size):
    return (size + 0xFFF) & 0xFFFFFFFFFFFFF000
