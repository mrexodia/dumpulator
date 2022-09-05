import unittest
from dumpulator.handles import *


class TestHandleManager(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hm = HandleManager()
        cls.handle_data = {
            "test": "test"
        }

    def test_single_handle(self):
        handle = self.hm.new(self.handle_data)
        self.assertEqual(handle, 0x100)
        self.hm.close(handle)

    def test_multiple_handles(self):
        handle_1 = self.hm.new(self.handle_data)
        handle_2 = self.hm.new(self.handle_data)
        handle_3 = self.hm.new(self.handle_data)
        handle_4 = self.hm.new(self.handle_data)
        self.assertEqual(handle_1, 0x100)
        self.assertEqual(handle_2, 0x104)
        self.assertEqual(handle_3, 0x108)
        self.assertEqual(handle_4, 0x10C)
        self.hm.close(handle_1)
        self.hm.close(handle_2)
        self.hm.close(handle_3)
        self.hm.close(handle_4)

    def test_get_handle(self):
        handle = self.hm.new(self.handle_data)
        data = self.hm.get(handle)
        self.assertEqual(data, self.handle_data)
        self.hm.close(handle)

    def test_duplicate_handle(self):
        handle = self.hm.new(self.handle_data)
        dup_handle = self.hm.duplicate(handle)
        self.hm.close(handle)
        data = self.hm.get(dup_handle)
        self.assertEqual(data, self.handle_data)
        self.hm.close(dup_handle)
        with self.assertRaises(AssertionError):
            self.hm.get(dup_handle)

    def test_add_handle(self):
        handle = 0x10
        self.hm.add(handle, self.handle_data)
        data = self.hm.get(handle)
        self.assertEqual(data, self.handle_data)
        self.hm.close(handle)
        with self.assertRaises(AssertionError):
            self.hm.get(handle)

    def test_add_handle_assert(self):
        handle = 0x10
        self.hm.add(handle)
        with self.assertRaises(AssertionError):
            self.hm.add(handle)
        self.hm.close(handle)

    def test_get_handle_assert(self):
        with self.assertRaises(AssertionError):
            self.hm.get(1)

    def test_close_handle_assert(self):
        with self.assertRaises(AssertionError):
            self.hm.close(1)

    def test_duplicate_handle_assert(self):
        with self.assertRaises(AssertionError):
            self.hm.duplicate(1)


if __name__ == '__main__':
    unittest.main()
