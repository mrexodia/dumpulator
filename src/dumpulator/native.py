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

# ntioapi.h
FILE_SUPERSEDED = 0x00000000
FILE_OPENED = 0x00000001
FILE_CREATED = 0x00000002
FILE_OVERWRITTEN = 0x00000003
FILE_EXISTS = 0x00000004
FILE_DOES_NOT_EXIST = 0x00000005

def round_to_pages(size):
    return (size + 0xFFF) & 0xFFFFFFFFFFFFF000
