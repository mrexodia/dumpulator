#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import struct
import ntpath
from .common_structs import *
from .streams.SystemInfoStream import PROCESSOR_ARCHITECTURE

class VirtualSegment:
	def __init__(self, start, end, start_file_address):
		self.start = start
		self.end = end
		self.start_file_address = start_file_address

		

		self.data = None
	
	def inrange(self, start, end):
		return self.start <= start and end<= self.end

class MinidumpBufferedMemorySegment:
	def __init__(self, memory_segment, file_handle, chunksize = 10*1024):
		self.start_address = memory_segment.start_virtual_address
		self.end_address = memory_segment.end_virtual_address
		self.total_size = memory_segment.end_virtual_address - memory_segment.start_virtual_address
		self.start_file_address = memory_segment.start_file_address
		self.chunksize = chunksize
		self.chunks = []

	def inrange(self, position):
		return self.start_address <= position < self.end_address

	def remaining_len(self, position):
		return self.end_address - position if self.inrange(position) else None

	def find(self, file_handle, pattern, startpos):
		data = self.read(file_handle, 0, -1)
		return data.find(pattern, startpos)

	def read(self, file_handle, start, end):
		if end is None:
			file_handle.seek(self.start_file_address + start)
			return file_handle.read(self.end_address - (self.start_file_address + start))
		
		for chunk in self.chunks:
			if chunk.inrange(start, end):
				return chunk.data[start - chunk.start: end - chunk.start]
		
		if self.total_size <= 2*self.chunksize:
			chunksize = self.total_size
			vs = VirtualSegment(0, chunksize, self.start_file_address)
			file_handle.seek(self.start_file_address)
			vs.data = file_handle.read(chunksize)
			self.chunks.append(vs)
			return vs.data[start - vs.start: end - vs.start]

		chunksize = max((end-start), self.chunksize)
		if start + chunksize > self.end_address:
			chunksize = self.end_address - start
		
		vs = VirtualSegment(start, start+chunksize, self.start_file_address + start)
		file_handle.seek(vs.start_file_address)
		vs.data = file_handle.read(chunksize)
		self.chunks.append(vs)
		
		return vs.data[start - vs.start: end - vs.start]



class MinidumpBufferedReader:
	def __init__(self, reader, segment_chunk_size = 10*1024):
		self.reader = reader
		self.segment_chunk_size = segment_chunk_size
		self.memory_segments = []

		self.current_segment = None
		self.current_position = None

	def _select_segment(self, requested_position):
		"""

		"""
		# check if we have semgnet for requested address in cache
		for memory_segment in self.memory_segments:
			if memory_segment.inrange(requested_position):
				self.current_segment = memory_segment
				self.current_position = requested_position
				return

		# not in cache, check if it's present in memory space. if yes then create a new buffered memeory object, and copy data
		for memory_segment in self.reader.memory_segments:
			if memory_segment.inrange(requested_position):
				newsegment = MinidumpBufferedMemorySegment(memory_segment, self.reader.file_handle, chunksize=self.segment_chunk_size)
				self.memory_segments.append(newsegment)
				self.current_segment = newsegment
				self.current_position = requested_position
				return

		raise Exception('Memory address 0x%08x is not in process memory space' % requested_position)

	def get_reader(self):
		return self.reader

	def seek(self, offset, whence = 0):
		"""
		Changes the current address to an offset of offset. The whence parameter controls from which position should we count the offsets.
		0: beginning of the current memory segment
		1: from current position
		2: from the end of the current memory segment
		If you wish to move out from the segment, use the 'move' function
		"""
		if whence == 0:
			t = self.current_segment.start_address + offset
		elif whence == 1:
			t = self.current_position + offset
		elif whence == 2:
			t = self.current_segment.end_address - offset
		else:
			raise Exception('Seek function whence value must be between 0-2')

		if not self.current_segment.inrange(t):
			raise Exception('Seek would cross memory segment boundaries (use move)')

		self.current_position = t
		return

	def move(self, address):
		"""
		Moves the buffer to a virtual address specified by address
		"""
		self._select_segment(address)
		return

	def align(self, alignment = None):
		"""
		Repositions the current reader to match architecture alignment
		"""
		if alignment is None:
			if self.reader.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.AMD64:
				alignment = 8
			else:
				alignment = 4
		offset = self.current_position % alignment
		if offset == 0:
			return
		offset_to_aligned = (alignment - offset) % alignment
		self.seek(offset_to_aligned, 1)
		return

	def tell(self):
		"""
		Returns the current virtual address
		"""
		return self.current_position

	def peek(self, length):
		"""
		Returns up to length bytes from the current memory segment
		"""
		t = self.current_position + length
		if not self.current_segment.inrange(t):
			raise Exception('Would read over segment boundaries!')
		return self.current_segment.read(self.reader.file_handle, self.current_position - self.current_segment.start_address , t - self.current_segment.start_address)

	def read(self, size = -1):
		"""
		Returns data bytes of size size from the current segment. If size is -1 it returns all the remaining data bytes from memory segment
		"""
		if size < -1:
			raise Exception('You shouldnt be doing this')
		if size == -1:
			t = self.current_segment.remaining_len(self.current_position)
			if not t:
				return None

			old_new_pos = self.current_position
			self.current_position = self.current_segment.end_address
			return self.current_segment.read(self.reader.file_handle, old_new_pos - self.current_segment.start_address, None)

		t = self.current_position + size
		if not self.current_segment.inrange(t - 1):
			raise Exception('Would read over segment boundaries!')

		old_new_pos = self.current_position
		self.current_position = t
		return self.current_segment.read(self.reader.file_handle, old_new_pos - self.current_segment.start_address, t - self.current_segment.start_address)

	def read_int(self):
		"""
		Reads an integer. The size depends on the architecture.
		Reads a 4 byte small-endian singed int on 32 bit arch
		Reads an 8 byte small-endian singed int on 64 bit arch
		"""
		if self.reader.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.AMD64:
			return int.from_bytes(self.read(8), byteorder = 'little', signed = True)
		else:
			return int.from_bytes(self.read(4), byteorder = 'little', signed = True)

	def read_uint(self):
		"""
		Reads an integer. The size depends on the architecture.
		Reads a 4 byte small-endian unsinged int on 32 bit arch
		Reads an 8 byte small-endian unsinged int on 64 bit arch
		"""
		if self.reader.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.AMD64:
			return int.from_bytes(self.read(8), byteorder = 'little', signed = False)
		else:
			return int.from_bytes(self.read(4), byteorder = 'little', signed = False)

	def find(self, pattern):
		"""
		Searches for a pattern in the current memory segment
		"""
		pos = self.current_segment.find(self.reader.file_handle, pattern)
		return -1 if pos == -1 else pos + self.current_position

	def find_all(self, pattern):
		"""
		Searches for all occurrences of a pattern in the current memory segment, returns all occurrences as a list
		"""
		pos = []
		last_found = -1
		while True:
			last_found = self.current_segment.find(self.reader.file_handle, pattern, last_found + 1)
			if last_found == -1:
				break
			pos.append(last_found + self.current_segment.start_address)

		return pos

	def find_global(self, pattern):
		"""
		Searches for the pattern in the whole process memory space and returns the first occurrence.
		This is exhaustive!
		"""
		pos_s = self.reader.search(pattern)
		return -1 if len(pos_s) == 0 else pos_s[0]

	def find_all_global(self, pattern):
		"""
		Searches for the pattern in the whole process memory space and returns a list of addresses where the pattern begins.
		This is exhaustive!
		"""
		return self.reader.search(pattern)

	def get_ptr(self, pos):
		self.move(pos)
		return self.read_uint()
		#raw_data = self.read(pos, self.sizeof_ptr)
		#return struct.unpack(self.unpack_ptr, raw_data)[0]

	def get_ptr_with_offset(self, pos):
		if self.reader.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.AMD64:
			self.move(pos)
			ptr = int.from_bytes(self.read(4), byteorder = 'little', signed = True)
			return pos + 4 + ptr
		else:
			self.move(pos)
			return self.read_uint()

	def find_in_module(self, module_name, pattern, find_first = False, reverse_order = False):
		return self.reader.search_module(
			module_name,
			pattern,
			find_first=find_first,
			reverse_order=reverse_order,
			chunksize=self.segment_chunk_size,
		)




class MinidumpFileReader:
	def __init__(self, minidumpfile):
		self.modules = minidumpfile.modules.modules
		self.unloaded_modules = []
		if minidumpfile.unloaded_modules is not None:
			self.unloaded_modules = minidumpfile.unloaded_modules.modules

		self.sysinfo = minidumpfile.sysinfo

		if minidumpfile.memory_segments_64:
			self.memory_segments = minidumpfile.memory_segments_64.memory_segments
			self.is_fulldump = True

		else:
			self.memory_segments = minidumpfile.memory_segments.memory_segments
			self.is_fulldump = False

		self.filename = minidumpfile.filename
		self.file_handle = minidumpfile.file_handle

		#reader params
		self.sizeof_long = 4
		self.unpack_long = '<L'
		if minidumpfile.sysinfo.ProcessorArchitecture in [PROCESSOR_ARCHITECTURE.AMD64, PROCESSOR_ARCHITECTURE.AARCH64]:
			self.sizeof_ptr = 8
			self.unpack_ptr = '<Q'
		elif self.sysinfo.ProcessorArchitecture in [PROCESSOR_ARCHITECTURE.INTEL,
				PROCESSOR_ARCHITECTURE.ARM]:
			self.sizeof_ptr = 4
			self.unpack_ptr = '<L'
		else:
			raise Exception(
				f'Unknown processor architecture {self.sysinfo.ProcessorArchitecture}! Please fix and submit PR!'
			)

	def get_handler(self):
		return self.file_handle

	def get_memory(self):
		return self.memory_segments

	def get_buffered_reader(self, segment_chunk_size = 10*1024):
		return MinidumpBufferedReader(self, segment_chunk_size = segment_chunk_size)

	def get_module_by_name(self, module_name):
		return next(
			(
				mod
				for mod in self.modules
				if ntpath.basename(mod.name).lower().find(module_name.lower()) != -1
			),
			None,
		)

	def get_unloaded_by_name(self, module_name):
		return next(
			(
				mod
				for mod in self.unloaded_modules
				if ntpath.basename(mod.name).find(module_name) != -1
			),
			None,
		)

	def search_module(self, module_name, pattern, find_first = False, reverse_order = False, chunksize = 10*1024):
		mod = self.get_module_by_name(module_name)
		if mod is None:
			mod = self.get_unloaded_by_name(module_name)
		if mod is None:
			raise Exception(f'Could not find module! {module_name}')

		needles = []
		for ms in self.memory_segments:
			if mod.baseaddress <= ms.start_virtual_address < mod.endaddress:
				needles+= ms.search(pattern, self.file_handle, find_first = find_first, chunksize = chunksize)
				if len(needles) > 0 and find_first is True:
					return needles


		return needles

	def search(self, pattern, find_first = False, chunksize = 10*1024):
		t = []
		for ms in self.memory_segments:
			t+= ms.search(pattern, self.file_handle, find_first = find_first, chunksize = chunksize)

		return t

	def read(self, virt_addr, size):
		for segment in self.memory_segments:
			if segment.inrange(virt_addr):
				return segment.read(virt_addr, size, self.file_handle)
		raise Exception(f'Address not in memory range! {hex(virt_addr)}')

