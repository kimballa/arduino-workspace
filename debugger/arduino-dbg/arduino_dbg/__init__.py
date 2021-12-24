# (c) Copyright 2021 Aaron Kimball

import argparse
from elftools.elf.elffile import ELFFile
import serial


class Debugger(object):
    """
        Main debugger state object.
    """

    def __init__(self, elf_name, port, baud=9600, timeout=1):
        self._conn = None
        self.reopen(port, baud, timeout)
        self.elf_name = elf_name

    def close(self):
        """
            Close serial connection.
        """
        self._conn.close()
        self._conn = None

    def reopen(self, port, baud, timeout):
        """
          (Re)establish serial connection.
        """
        if self._conn is not None:
            self.close()

        if port is not None and port != '':
            self._conn = serial.Serial(port, baud, timeout=timeout)

    def read_elf(self):
        """
            Read the target ELF file and print some stuff.
        """
        if self.elf_name is None:
            print("No ELF filename given")
            return

        with open(self.elf_name, 'rb') as f:
            elf = ELFFile(f)
            if not elf.has_dwarf_info():
                print("Warning: No debug info (DWARF) in ELF file")

            for sect in elf.iter_sections():
                print("Section: %s at offset 0x%.8x with size %d" % (sect.name,
                    sect.header['sh_offset'], sect.header['sh_size']))

            dwarfinfo = elf.get_dwarf_info()
            if dwarfinfo is not None:
                pub_names = dwarfinfo.get_pubnames()
                if pub_names is None:
                    print("Error: No .debug_pubnames section")
                else:
                    for name, entry in pub_names.items():
                        print("%s" % name)

            syms = elf.get_section_by_name(".symtab")
            if syms is not None:
                print("*** Symbols (.symtab)")
                for sym in syms.iter_symbols():
                    print("%s: %s" % (sym.name, sym.entry))



    
def _parseArgs():
    parser = argparse.ArgumentParser(description="Serial debugger client for Arduino apps")
    parser.add_argument("-p", "--port", required=True)
    parser.add_argument("-f", "--file", metavar="elf_file")

    return parser.parse_args()

def main(argv):
    args = _parseArgs()
    d = Debugger(args.file, args.port)
    d.read_elf()
