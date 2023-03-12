import struct
from typing import Optional

from dumpulator import Dumpulator
from dumpulator.handles import DeviceObject, DeviceControlData, ConsoleFileObject

# References:
# - https://github.com/dlunch/NewConsole/blob/245fca3b3e3ed469b231a9d8b6fda3282782bac1/NewConsole/ConsoleHost.cpp#L196-L306
# - https://www.unknowncheats.me/forum/c-and-c-/467307-using-console-via-ioctl.html
class ConsoleDeviceObject(DeviceObject):
    def io_control(self, dp: Dumpulator, control: DeviceControlData) -> Optional[bytes]:
        if control.code == 0x500016:  # ConsoleCallServerGeneric
            print(f"console: ConsoleCallServerGeneric(")
            # TODO: this changed in Windows 10, Windows 8.1/7 uses a different structure
            assert dp.ptr_size() == 8 or dp.wow64  # TODO: support 32-bit

            console_handle = control.read_ulonglong()
            console_file = dp.handles.get(console_handle, ConsoleFileObject)
            assert console_file is not None
            unk1 = control.read_ulong()
            unk2 = control.read_ulong()
            assert unk1 == unk2 and unk1 == 1  # TODO: which is which?
            unk3 = control.read_ulong()
            control.skip(4)  # padding
            data_ptr = control.read_ulonglong()
            result_size = control.read_ulong()
            control.skip(4)  # padding
            result_ptr = control.read_ulonglong()

            # TODO: refactor this into a generic call logger
            print(f"    ConsoleHandle = {hex(console_handle)} /* {console_file} */")
            print(f"    unk1 = {hex(unk1)}")
            print(f"    unk2 = {hex(unk2)}")
            print(f"    unk3 = {hex(unk3)}")
            print(f"    data_ptr = {hex(data_ptr)}")
            print(f"    result_size = {hex(result_size)}")
            print(f"    result_ptr = {hex(result_ptr)}")
            print(")")

            request_data = dp.read(data_ptr, unk1 * 8)
            request_code, request_unk_size = struct.unpack("<II", request_data)

            if request_code == 0x1000000:  # GetConsoleCP
                raise NotImplementedError()
            elif request_code == 0x1000001:  # GetConsoleMode
                assert result_size == 4
                dp.write_ulong(result_ptr, console_file.mode)
                return None
            elif request_code == 0x2000007:  # GetConsoleScreenBufferInfoEx
                raise NotImplementedError()
            elif request_code == 0x1000006:  # WriteConsole
                raise NotImplementedError()
            elif request_code == 0x1000005:  # ReadConsole
                raise NotImplementedError()
            elif request_code == 0x2000014:  # GetConsoleTitle
                raise NotImplementedError()
            elif request_code == 0x1000002:  # SetConsoleMode
                raise NotImplementedError()
            elif request_code == 0x1000008:  # SetTEBLangID
                raise NotImplementedError()
            elif request_code == 0x2000015:  # SetConsoleTitle
                raise NotImplementedError()
            elif request_code == 0x200000a:  # SetConsoleCursorPosition
                raise NotImplementedError()
            elif request_code == 0x200000d:  # SetConsoleTextAttribute
                raise NotImplementedError()
            elif request_code == 0x2000000:  # FillConsoleOutput
                raise NotImplementedError()
            elif request_code == 0x300001f:  # GetConsoleWindow
                raise NotImplementedError()
            elif request_code == 0x3000004:  # ?? Called by powershell
                raise NotImplementedError()
            else:
                raise NotImplementedError()
        elif control.code == 0x500037:  # ConsoleLaunchServerProcess (AllocConsole)
            raise NotImplementedError()
        else:
            raise NotImplementedError()
