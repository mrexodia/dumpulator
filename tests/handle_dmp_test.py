import unittest
from dumpulator import Dumpulator
from dumpulator.native import *


class TestHandleManagerx64(unittest.TestCase):
    dp = None

    @classmethod
    def setUp(cls):
        cls.dp = Dumpulator("TestHarness_x64.dmp", quiet=True)
        with open("TestHarness/bin/HandleTest_x64.dll", "rb") as dll:
            dll_data = dll.read()
            cls.dp.map_module(dll_data, "HandleTest_x64.dll")

    def test_write_create_file(self):
        self.dp.handles.create_file("nonexistant_file.txt", FILE_CREATE)
        test_func = self.dp.modules["HandleTest_x64.dll"].find_export("WriteAndCreateFileTest")
        ret_val = self.dp.call(test_func.address)
        self.assertEqual(ret_val, 1)

    def test_read_file(self):
        self.dp.handles.create_file("test_file.txt", FILE_OPEN)
        test_func = self.dp.modules["HandleTest_x64.dll"].find_export("ReadFileTest")
        ret_val = self.dp.call(test_func.address)
        self.assertEqual(ret_val, 1)


class TestHandleManagerx86(unittest.TestCase):
    dp = None

    @classmethod
    def setUp(cls):
        cls.dp = Dumpulator("TestHarness_x86.dmp", quiet=True)
        with open("TestHarness/bin/HandleTest_x86.dll", "rb") as dll:
            dll_data = dll.read()
            cls.dp.map_module(dll_data, "HandleTest_x86.dll")

    def test_write_create_file(self):
        self.dp.handles.create_file("nonexistant_file.txt", FILE_CREATE)
        test_func = self.dp.modules["HandleTest_x86.dll"].find_export("WriteAndCreateFileTest")
        ret_val = self.dp.call(test_func.address)
        self.assertEqual(ret_val, 1)

    def test_read_file(self):
        self.dp.handles.create_file("test_file.txt", FILE_OPEN)
        test_func = self.dp.modules["HandleTest_x86.dll"].find_export("ReadFileTest")
        ret_val = self.dp.call(test_func.address)
        self.assertEqual(ret_val, 1)


if __name__ == '__main__':
    unittest.main()
