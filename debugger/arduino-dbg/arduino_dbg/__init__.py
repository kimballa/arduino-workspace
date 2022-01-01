# (c) Copyright 2021 Aaron Kimball

import argparse
from elftools.elf.elffile import ELFFile
import locale
import serial
import subprocess


def _demangle(name):
    """
        Use c++filt in binutils to demangle a C++ name into a human-readable one.
    """
    args = ['c++filt', '-t', name]
    pipe = subprocess.Popen(args, stdin=None, stdout=subprocess.PIPE,
        encoding=locale.getpreferredencoding())
    stdout, _ = pipe.communicate()
    demangled = stdout.split("\n")
    return demangled[0]


def _pc_to_source_line(elf_file, addr):
    """
        Given a program counter ($PC) value, establish what line of source it comes from.
    """
    args = ["addr2line", "-s", "-e", elf_file, ("%x" % addr)]
    pipe = subprocess.Popen(args, stdin=None, stdout=subprocess.PIPE,
        encoding=locale.getpreferredencoding())
    stdout, _ = pipe.communicate()
    source_lines = stdout.split("\n")
    return source_lines[0]


class Debugger(object):
    """
        Main debugger state object.
    """

    def __init__(self, elf_name, port, baud=57600, timeout=1):
        self._conn = None
        self.reopen(port, baud, timeout)
        self.elf_name = elf_name
        self._sections = {}
        self._addr_to_symbol = {}
        self._symbols = {}

        self._read_elf()


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


    def sym_for_addr(self, addr):
        """
            Return the name of the symbol keyed to a particular address.
        """
        return self._addr_to_symbol[addr]


    def function_sym_by_pc(self, pc):
        """
            Given a $PC pointing somewhere within a function body, return the name of
            the symbol for the function.
        """
        for (addr, name) in self._addr_to_symbol.items():
            if addr > pc:
                continue # Definitely not this one.

            sym = self._symbols[name]
            if sym['st_info']['type'] != "STT_FUNC":
                continue # Not a function

            if addr + sym['st_size'] >= pc:
                return name # Found it.


    def _read_elf(self):
        """
            Read the target ELF file to load debugging information.
        """
        if self.elf_name is None:
            print("No ELF filename given")
            return

        with open(self.elf_name, 'rb') as f:
            elf = ELFFile(f)

            for sect in elf.iter_sections():
                my_section = {}
                my_section["name"] = sect.name
                my_section["size"] = sect.header['sh_size']
                my_section["offset"] = sect.header['sh_offset']
                self._sections[sect.name] = my_section

                #print("Section: %s at offset 0x%.8x with size %d" % (sect.name,
                #    sect.header['sh_offset'], sect.header['sh_size']))

            syms = elf.get_section_by_name(".symtab")
            if syms is not None:
                for sym in syms.iter_symbols():
                    sym_type = sym.entry['st_info']['type']
                    if sym_type == "STT_NOTYPE" or sym_type == "STT_OBJECT" or sym_type == "STT_FUNC":
                        # This has a location worth memorizing
                        self._addr_to_symbol[sym.entry['st_value']] = sym.name
                        continue
                    self._symbols[sym.name] = sym


                #print("*** Symbols (.symtab)")
                #for sym in syms.iter_symbols():
                #    print("%s: %s" % (sym.name, sym.entry))

        # Sort the symbols by address
        self._addr_to_symbol = dict(sorted(self._addr_to_symbol.items()))
        for (addr, name) in self._addr_to_symbol.items():
            print("%08x => %s (%s)" % (addr, name, _demangle(name)))



def _parseArgs():
    parser = argparse.ArgumentParser(description="Serial debugger client for Arduino apps")
    parser.add_argument("-p", "--port", required=True)
    parser.add_argument("-f", "--file", metavar="elf_file")

    return parser.parse_args()

def main(argv):
    args = _parseArgs()
    d = Debugger(args.file, args.port)
