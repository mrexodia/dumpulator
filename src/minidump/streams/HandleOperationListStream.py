#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
class MINIDUMP_HANDLE_OPERATION_LIST:
	def __init__(self):
		self.SizeOfHeader = None
		self.SizeOfEntry = None
		self.NumberOfEntries = None
		self.Reserved = None
	
	@staticmethod
	def parse(dir, buff):
		mhds = MINIDUMP_HANDLE_OPERATION_LIST()
		mhds.SizeOfHeader = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mhds.SizeOfEntry = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mhds.NumberOfEntries = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mhds.Reserved = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
			
		return mhds
		