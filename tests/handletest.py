import unittest
from dumpulator.handles import *


class TestHandleManager(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.handles = HandleManager()
        cls.file_handle = FileObject("test.txt")

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
        data = self.handles.get(handle, FileObject)
        self.assertEqual(data, self.file_handle)
        self.handles.close(handle)

    def test_duplicate_handle(self):
        handle_data = FileObject("dupe.txt")
        handle = self.handles.new(handle_data)
        dup_handle = self.handles.duplicate(handle)
        self.assertEqual(self.handles.close(handle), True)
        data = self.handles.get(dup_handle, FileObject)
        self.assertEqual(data, handle_data)
        self.assertEqual(self.handles.close(dup_handle), True)

    def test_add_handle(self):
        handle = 0x10
        self.handles.add(handle, self.file_handle)
        data = self.handles.get(handle, FileObject)
        self.assertEqual(data, self.file_handle)
        self.handles.close(handle)
        with self.assertRaises(AssertionError):
            self.handles.get(handle, FileObject)

    def test_add_handle_assert(self):
        handle = 0x10
        self.handles.add(handle, FileObject(""))
        with self.assertRaises(AssertionError):
            self.handles.add(handle, FileObject(""))
        self.handles.close(handle)

    def test_get_handle_assert(self):
        with self.assertRaises(AssertionError):
            self.handles.get(1, None)

    def test_close_handle_assert(self):
        self.assertEqual(self.handles.close(1), False)

    def test_duplicate_handle_assert(self):
        with self.assertRaises(AssertionError):
            self.handles.duplicate(1)

    def test_file_object_read(self):
        file_data = b"file_data"
        file = FileObject("file_path", file_data)

        # test read no given size
        self.assertEqual(file_data, file.read())
        self.assertEqual(file.file_offset, len(file_data))
        file.file_offset = 0

        # test read with given size
        self.assertEqual(b"file", file.read(4))
        self.assertEqual(4, file.file_offset)
        file.file_offset = 0

        # test read with file offset not 0
        file.file_offset = 5
        self.assertEqual(b"data", file.read())
        self.assertEqual(9, file.file_offset)

        # test read with file offset not 0 and with given size
        file.file_offset = 5
        self.assertEqual(b"data", file.read(4))
        self.assertEqual(9, file.file_offset)

        empty_file = FileObject("empty_file")
        self.assertEqual(b"", empty_file.read())

    def test_file_object_write(self):
        file_data = b"file_data"
        new_buffer = b"test_buffer"
        file = FileObject("file_path", file_data)

        # test write no given size
        file.write(new_buffer)
        self.assertEqual(new_buffer, file.data)
        self.assertEqual(len(new_buffer), file.file_offset)
        file.data = file_data
        file.file_offset = 0

        # test write given size
        file.write(new_buffer, 4)
        self.assertEqual(b"test_data", file.data)
        self.assertEqual(4, file.file_offset)
        file.data = file_data
        file.file_offset = 0

        # test write no given size with file offset
        file.file_offset = 5
        file.write(new_buffer)
        self.assertEqual(b"file_test_buffer", file.data)
        self.assertEqual(5 + len(new_buffer), file.file_offset)
        file.data = file_data
        file.file_offset = 0

        # test write given size with file offset
        file.file_offset = 5
        file.write(new_buffer, 4)
        self.assertEqual(b"file_test", file.data)
        self.assertEqual(9, file.file_offset)
        file.data = file_data
        file.file_offset = 0

if __name__ == '__main__':
    unittest.main()
