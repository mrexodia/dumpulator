import unittest
from dumpulator.handles import *


class TestHandleManager(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.handles = HandleManager()
        cls.file_handle = FileHandle("test.txt")
        cls.special_file_handle = SpecialFileHandle("test.txt", 1337)

    def test_single_handle(self):
        handle = self.handles.new(self.file_handle)
        self.assertEqual(handle, 0x100)
        self.handles.close(handle)

    def test_multiple_handles(self):
        handle_1 = self.handles.new(self.file_handle)
        handle_2 = self.handles.new(self.file_handle)
        handle_3 = self.handles.new(self.file_handle)
        handle_4 = self.handles.new(self.file_handle)
        self.assertEqual(handle_1, 0x100)
        self.assertEqual(handle_2, 0x104)
        self.assertEqual(handle_3, 0x108)
        self.assertEqual(handle_4, 0x10C)
        self.handles.close(handle_1)
        self.handles.close(handle_2)
        self.handles.close(handle_3)
        self.handles.close(handle_4)

    def test_get_handle(self):
        handle = self.handles.new(self.file_handle)
        data = self.handles.get(handle, FileHandle)
        self.assertEqual(data, self.file_handle)
        self.handles.close(handle)

    def test_duplicate_handle(self):
        handle_data = FileHandle("dupe.txt")
        handle = self.handles.new(handle_data)
        dup_handle = self.handles.duplicate(handle)
        self.assertEqual(self.handles.close(handle), True)
        data = self.handles.get(dup_handle, FileHandle)
        self.assertEqual(data, handle_data)
        self.assertEqual(self.handles.close(dup_handle), True)

    def test_add_handle(self):
        handle = 0x10
        self.handles.add(handle, self.file_handle)
        data = self.handles.get(handle, FileHandle)
        self.assertEqual(data, self.file_handle)
        self.handles.close(handle)
        with self.assertRaises(AssertionError):
            self.handles.get(handle, FileHandle)

    def test_add_handle_assert(self):
        handle = 0x10
        self.handles.add(handle)
        with self.assertRaises(AssertionError):
            self.handles.add(handle)
        self.handles.close(handle)

    def test_get_handle_assert(self):
        with self.assertRaises(AssertionError):
            self.handles.get(1, None)

    def test_close_handle_assert(self):
        self.assertEqual(self.handles.close(1), False)

    def test_duplicate_handle_assert(self):
        with self.assertRaises(AssertionError):
            self.handles.duplicate(1)


if __name__ == '__main__':
    unittest.main()
