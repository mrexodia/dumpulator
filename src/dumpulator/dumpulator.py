import minidump
import unicorn
import pefile

class Dumpulator:
    def __init__(self, minidump_file):
        self.minidump_file = minidump_file
