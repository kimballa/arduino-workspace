# (c) Copyright 2022 Aaron Kimball

import arduino_dbg.binutils as binutils

class Symbol(object):
    """
    An internal symbol table entry; represents a single named symbol.
    This has references to other information from the DWARF debug info:
    - main symbol table entry (addr <--> symbol name)
    - type info from .debug_info
    - call frame info from .debug_frame (for method symbols)

    as well as other internal cached data
    """

    def __init__(self, elf_sym):
        self.name = elf_sym.name
        self.size = elf_sym.entry['st_size']
        self.addr = elf_sym.entry['st_value']
        self.demangled = binutils.demangle(self.name)
        self.elf_sym = elf_sym
        self.type_info = None
        self.frame_info = None

    def setTypeInfo(self, type_info):
        self.type_info = type_info

    def setFrameInfo(self, frame_info):
        self.frame_info = frame_info

    def __repr__(self):
        name = f'{self.name}'
        typ = ''

        if self.name != self.demangled:
            name = f'{self.demangled} ({self.name})'
        if self.type_info:
            typ = f' : {self.type_info.name}'

        return f'{name} @ {self.addr:04x} <len={self.size}>{typ}'



