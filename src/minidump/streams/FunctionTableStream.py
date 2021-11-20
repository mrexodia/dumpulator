#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
class MINIDUMP_FUNCTION_TABLE_STREAM:
	def __init__(self):
		self.SizeOfHeader = None
		self.SizeOfDescriptor = None
		self.SizeOfNativeDescriptor = None
		self.SizeOfFunctionEntry = None
		self.NumberOfDescriptors = None
		self.SizeOfAlignPad = None
	
	@staticmethod
	def parse(dir, buff):
		mfts = MINIDUMP_FUNCTION_TABLE_STREAM()
		mfts.SizeOfHeader = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mfts.SizeOfDescriptor = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mfts.SizeOfNativeDescriptor = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mfts.SizeOfFunctionEntry = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mfts.NumberOfDescriptors = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mfts.SizeOfAlignPad = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
			
		return mfts