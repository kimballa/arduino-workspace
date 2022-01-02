# (c) Copyright 2021 Aaron Kimball

from elftools.elf.elffile import ELFFile
import importlib.resources as resources
import serial
import arduino_dbg.binutils as binutils

_dbg_conf_keys = [
    "arduino.platform",
    "arduino.arch",
]

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

        self._config = {} # General user-accessible config.
        for k in _dbg_conf_keys:
            self._config[k] = None
        self._platform = {} # Arduino platform-specific config
        self._arch = {} # CPU architecture-specific config

        self._read_elf()
        self._load_platform()

    def _load_platform(self):
        """
            If the arduino.platform key is set, use it to load the platform-specific config.
        """
        platform_name = self.get_conf("arduino.platform")
        if platform_name is None or len(platform_name) == 0:
            return # Nothing to load.

        conf_resource_name = platform_name.strip() + ".conf"
        conf_text = resources.read_text("arduino_dbg.platforms", conf_resource_name)
        conf = {}
        eval(conf_text, conf, conf)
        self._platform = conf

        print("Loading platform profile: %s; read %d keys" % (conf_resource_name, len(self._platform)))
        self.set_conf("arduino.arch", self._platform["arch"])
        self._load_arch() # New platform => new architecture; refresh this too.

    def _load_arch(self):
        """
            If the arduino.arch key is set, use it to load the arch-specific config.
        """
        arch_name = self.get_conf("arduino.arch")
        if arch_name is None or len(arch_name) == 0:
            return # Nothing to load.

        conf_resource_name = arch_name.strip() + ".conf"
        conf_text = resources.read_text("arduino_dbg.arch", conf_resource_name)
        conf = {}
        eval(conf_text, conf, conf)
        self._arch = conf
        print("Loading arch profile: %s; read %d keys" % (conf_resource_name, len(self._arch)))


    def set_conf(self, key, val):
        """
            Set a key/value pair in the configuration map.
            Then process any triggers associated w/ that key.
        """
        if key not in _dbg_conf_keys:
            raise KeyError("Not a valid conf key: %s" % key)
        self._config[key] = val

    def get_conf(self, key):
        if key not in _dbg_conf_keys:
            raise KeyError("Not a valid conf key: %s" % key)
        return self._config[key]

    def get_full_config(self):
        return self._config.items()



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

    def is_open(self):
        return self._conn is not None and self._conn.is_open

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


    def breakpoint(self):
        """
            Break program execution and get the attention of the debug server.
        """
        pass

    RESULT_SILENT = 0
    RESULT_ONELINE = 1
    RESULT_LIST = 2

    def send_cmd(self, dbg_cmd, result_type):
        """
            Send a low-level debugger command across the wire and return the results.
            @param dbg_cmd either a formatted command string or list of cmd and arguments.
            @param result_type an integer/enum specifying whether to expect 0, 1, or 'n'
            ($-terminated list) lines in response.
        """

        if type(dbg_cmd) == list:
            dbg_cmd = dbg_cmd.join(" ") + "\n"

        if not self.is_open():
            print("Error: No debug server connection open")
            return None

        self._conn.write(dbg_cmd.encode("utf-8"))
        if result_type == RESULT_SILENT:
            return None
        elif result_type == RESULT_ONELINE:
            return self._conn.readline().strip()
        elif result_type == RESULT_LIST:
            lines = []
            while True:
                thisline = self._conn.readline().strip()
                if thisline == "$":
                    break
                else:
                    lines.append(thisline)
        else:
            raise RuntimeError("Invalid 'result_type' arg (%d) sent to send_cmd" % result_type)




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
            print("%08x => %s (%s)" % (addr, name, binutils.demangle(name)))

