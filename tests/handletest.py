import unittest
from dumpulator.handles import *


class TestHandleManager(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handles = HandleManager()
        cls.handle_data = {
            "test": "test"
        }

    def test_single_handle(self):
        handle = self.handles.new(self.handle_data)
        self.assertEqual(handle, 0x100)
        self.handles.close(handle)

    def test_multiple_handles(self):
        handle_1 = self.handles.new(self.handle_data)
        handle_2 = self.handles.new(self.handle_data)
        handle_3 = self.handles.new(self.handle_data)
        handle_4 = self.handles.new(self.handle_data)
        self.assertEqual(handle_1, 0x100)
        self.assertEqual(handle_2, 0x104)
        self.assertEqual(handle_3, 0x108)
        self.assertEqual(handle_4, 0x10C)
        self.handles.close(handle_1)
        self.handles.close(handle_2)
        self.handles.close(handle_3)
        self.handles.close(handle_4)

    def test_get_handle(self):
        handle = self.handles.new(self.handle_data)
        data = self.handles.get(handle)
        self.assertEqual(data, self.handle_data)
        self.handles.close(handle)

    def test_duplicate_handle(self):
        handle = self.handles.new(self.handle_data)
        dup_handle = self.handles.duplicate(handle)
        self.handles.close(handle)
        data = self.handles.get(dup_handle)
        self.assertEqual(data, self.handle_data)
        self.handles.close(dup_handle)
        with self.assertRaises(AssertionError):
            self.handles.get(dup_handle)

    def test_add_handle(self):
        handle = 0x10
        self.handles.add(handle, self.handle_data)
        data = self.handles.get(handle)
        self.assertEqual(data, self.handle_data)
        self.handles.close(handle)
        with self.assertRaises(AssertionError):
            self.handles.get(handle)

    def test_add_handle_assert(self):
        handle = 0x10
        self.handles.add(handle)
        with self.assertRaises(AssertionError):
            self.handles.add(handle)
        self.handles.close(handle)

    def test_get_handle_assert(self):
        with self.assertRaises(AssertionError):
            self.handles.get(1)

    def test_close_handle_assert(self):
        with self.assertRaises(AssertionError):
            self.handles.close(1)

    def test_duplicate_handle_assert(self):
        with self.assertRaises(AssertionError):
            self.handles.duplicate(1)


if __name__ == '__main__':
    unittest.main()
