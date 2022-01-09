# (c) Copyright 2021 Aaron Kimball

from elftools.elf.elffile import ELFFile
import importlib.resources as resources
import os
import serial
import time

import arduino_dbg.binutils as binutils
import arduino_dbg.protocol as protocol
import arduino_dbg.stack as stack
import arduino_dbg.types as types

_LOCAL_CONF_FILENAME = os.path.expanduser("~/.arduino_dbg.conf")
_DBG_CONF_FMT_VERSION = 1

_dbg_conf_keys = [
    "arduino.platform",
    "arduino.arch",
    "dbg.conf.formatversion",
    "dbg.verbose",
]

# When we connect to the device, which state are we in?
PROCESS_STATE_UNKNOWN = 0
PROCESS_STATE_RUNNING = 1
PROCESS_STATE_BREAK   = 2


def _silent(*args):
    """
        dummy method to turn verboseprint() calls to nothing
    """
    pass



def _load_conf_module(module_name, resource_name):
    """
        Open a resource (file) within a module with a '.conf' extension and treat it like python
        code; execute it in a sheltered environment and return the processed globals as a k-v map.

        We use this for Arduino Platform and cpu architecture (Arch) definitions.
    """
    if resource_name is None or len(resource_name) == 0:
        return None # Nothing to load.

    conf_resource_name = resource_name.strip() + ".conf"
    conf_text = resources.read_text(module_name, conf_resource_name)
    conf = {} # Create an empty environment in which to run the config code.

    def _include_fn(extra_resource_name):
        """
            Provide an 'include' method within the exec() scope so a .conf file can include
            more .conf files. This is restricted to the same module_name as the exterior binding
            scope.
        """
        included_map = _load_conf_module(module_name, extra_resource_name)
        # Copy the items from the included map into the namespace of the including conf file
        for (k, v) in included_map.items():
            conf[k] = v

        return None

    conf['include'] = _include_fn # Give the 'include' function to the scope.
    try:
        exec(conf_text, conf, conf)
        del conf["__builtins__"] # Pull python internals from gloabls map we're using as config.
        del conf["include"] # Pull out the include() function we provided.

        # Remove any "__private" items.
        to_delete = []
        for (k, v) in conf.items():
            if isinstance(k, str) and k.startswith("__"):
                to_delete.append(k)
        for key in to_delete:
            del conf[key]

    except:
        # Error parsing/executing conf; return empty result.
        print("Error loading config profile: %s" % conf_resource_name)
        return None

    print("Loading config profile: %s; read %d keys" % (conf_resource_name, len(conf)))
    # conf is now populated with the globals from executing the conf file.
    return conf


class Debugger(object):
    """
        Main debugger state object.
    """

    def __init__(self, elf_name, port, baud=57600, timeout=1):
        self._conn = None
        self.reopen(port, baud, timeout)
        self.elf_name = os.path.realpath(elf_name)
        self._sections = {}
        self._addr_to_symbol = {}
        self._symbols = {}
        self._demangled_to_symbol = {}
        self._dwarf_info = None
        self.elf = None
        self._elf_file_handle = None
        self.verboseprint = _silent # verboseprint() method is either _silent() or print()

        # General user-accessible config.
        # Load latest config from a dotfile in user's $HOME.
        self._init_config_from_file()

        self._read_elf()

        self._process_state = PROCESS_STATE_UNKNOWN

    ###### Configuration file / config key management functions.

    def _set_conf_defaults(self, conf_map=None):
        """
            Populate conf_map with all our config keys, and initialize any default values.
        """
        if conf_map is None:
            conf_map = {}

        for k in _dbg_conf_keys:
            conf_map[k] = None

        # If we open a file it can overwrite this but we start with this non-None default val.
        conf_map["dbg.conf.formatversion"] = _DBG_CONF_FMT_VERSION
        conf_map["dbg.verbose"] = False

        return conf_map

    def _init_config_from_file(self):
        """
            If the user has a config file (see _LOCAL_CONF_FILENAME) then initialize self._config
            from that.
        """
        new_conf = self._set_conf_defaults({})

        # The loaded config will be a map named 'config' within an otherwise-empty environment
        init_env = {}
        init_env['config'] = {}

        if os.path.exists(_LOCAL_CONF_FILENAME):
            with open(_LOCAL_CONF_FILENAME, "r") as f:
                conf_text = f.read()
                try:
                    exec(conf_text, init_env, init_env)
                except:
                    # error parsing or executing the config file.
                    print("Warning: error parsing config file '%s'" % _LOCAL_CONF_FILENAME)
                    init_env['config'] = {}

        try:
            fmtver = init_env['formatversion']
            if not isinstance(fmtver, int) or fmtver > _DBG_CONF_FMT_VERSION:
                print(f"Error: Cannot read config file '{_LOCAL_CONF_FILENAME}' with version {fmtver}")
                init_env['config'] = {} # Disregard the unsupported configuration data.

            loaded_conf = init_env['config']
        except:
            print(f"Error in format for config file '{_LOCAL_CONF_FILENAME}'")
            loaded_conf = {}


        # Merge loaded data on top of our default config.
        for (k, v) in loaded_conf.items():
            new_conf[k] = v

        self._config = new_conf
        self._platform = {} # Arduino platform-specific config (filled from conf file)
        self._arch = {} # CPU architecture-specific config (filled from conf file)
        self._config_verbose_print()

        self._load_platform() # cascade platform def from config, arch def from platform.

    def __persist_conf_var(self, f, k, v):
        """
            Persist k=v in serialized form to the file handle 'f'.

            Can be called with k=None to serialize a nested value in a complex type.
        """

        if k:
            f.write(f'  {repr(k)}: ')

        if v is None or type(v) == str or type(v) == int or type(v) == float or type(v) == bool:
            f.write(repr(v))
        elif type(v) == list:
            f.write('[')
            for elem in v:
                self.__persist_conf_var(f, None, elem)
                f.write(", ")
            f.write(']')
        elif type(v) == dict:
            f.write("{")
            for (dirK, dirV) in v.items():
                self.__persist_conf_var(f, None, dirK) # keys in a dir can be any type, not just str
                f.write(": ")
                self.__persist_conf_var(f, None, dirV)
                f.write(", ")
            f.write("}")
        else:
            print("Warning: unknown type serialization '%s'" % str(type(v)))
            # Serialize it as an abstract map; filter out python internals and methods
            objdir = dict([(dirK, dirV) for (dirK, dirV) in dir(v).items() if \
                (not dirK.startswith("__") and not dirK.endswith("__") and \
                not callable(getattr(v, dirK))) ])

            self.__persist_conf_var(f, None, objdir)

        if k:
            f.write(",\n")

    def _persist_config(self):
        """
            Write the current config out to a file to reload the next time we use the debugger.
        """

        # Don't let user session change this value; we know what serialization version we're
        # writing.
        self._config["dbg.conf.formatversion"] = _DBG_CONF_FMT_VERSION

        with open(_LOCAL_CONF_FILENAME, "w") as f:
            f.write(f"formatversion = {_DBG_CONF_FMT_VERSION}\n")
            f.write("config = {\n\n")
            for (k, v) in self._config.items():
                self.__persist_conf_var(f, k, v)
            f.write("\n}\n")


    def _load_platform(self):
        """
            If the arduino.platform key is set, use it to load the platform-specific config.
        """
        platform_name = self.get_conf("arduino.platform")
        if not platform_name:
            return
        new_conf = _load_conf_module("arduino_dbg.platforms", platform_name)
        if not new_conf:
            return

        self._platform = new_conf
        self.set_conf("arduino.arch", self._platform["arch"]) # Triggers refresh of arch config.


    def _load_arch(self):
        """
            If the arduino.arch key is set, use it to load the arch-specific config.
        """
        arch_name = self.get_conf("arduino.arch")
        if not arch_name:
            return
        new_conf = _load_conf_module("arduino_dbg.arch", arch_name)
        if not new_conf:
            return # Nothing to load.

        self._arch = new_conf


    def set_conf(self, key, val):
        """
            Set a key/value pair in the configuration map.
            Then process any triggers associated w/ that key.
        """
        if key not in _dbg_conf_keys:
            raise KeyError("Not a valid conf key: %s" % key)

        self._config[key] = val

        # Process triggers for specific keys
        if key == "arduino.platform":
            self._load_platform()
        if key == "arduino.arch":
            self._load_arch()
        if key == "dbg.verbose":
            self._config_verbose_print()

        self._persist_config() # Write changes to conf file.

    def _config_verbose_print(self):
        if self._config['dbg.verbose']:
            self.verboseprint = print
        else:
            self.verboseprint = _silent

    def get_conf(self, key):
        if key not in _dbg_conf_keys:
            raise KeyError("Not a valid conf key: %s" % key)
        return self._config[key]

    def get_full_config(self):
        """
            Return all user-configurable configuration key/val pairs.
            Does not include architecture or platform config.
        """
        return self._config.items()

    def get_arch_conf(self, key):
        """
            Return an architecture-specific property setting. These are read-only
            from outside the Debugger object. If the architecture is not set, or
            the architecture lacks the requested property definition, this returns None.
        """
        try:
            return self._arch[key]
        except KeyError:
            return None

    def get_platform_conf(self, key):
        """
            Return an Arduino platform-specific property setting. These are read-only
            from outside the Debugger object. If the platform name is not set, or
            the platform lacks the requested property definition, this returns None.
        """
        try:
            return self._platform[key]
        except KeyError:
            return None

    def get_full_arch_config(self):
        return self._arch.items()

    def get_full_platform_config(self):
        return self._platform.items()

    ###### ELF-file and symbol functions

    def close(self):
        """
            Clean up the debugger and release file resources.
        """
        if self._elf_file_handle:
            # Close the ELF file we opened at the beginning.
            self._elf_file_handle.close()
        self._elf_file_handle = None

    def _read_elf(self):
        """
            Read the target ELF file to load debugging information.
        """
        if self.elf_name is None:
            print("No ELF file provided; cannot load symbols")
            return

        self._elf_file_handle = open(self.elf_name, 'rb')
        self.elf = ELFFile(self._elf_file_handle)
        print(f"Loading image and symbols from {self.elf_name}")

        for elf_sect in self.elf.iter_sections():
            section = {}
            section["name"] = elf_sect.name
            section["size"] = elf_sect.header['sh_size']
            section["offset"] = elf_sect.header['sh_offset']
            section["addr"] = elf_sect.header['sh_addr']
            section["elf"] = elf_sect
            section["image"] = elf_sect.data()[0: section["size"]] # Copy out the section image data.
            self._sections[elf_sect.name] = section

            self.verboseprint("****************************")
            self.verboseprint(f'Section {elf_sect.name} has header {elf_sect.header}')
            self.verboseprint(f'off: {elf_sect.header["sh_offset"]}, size: {elf_sect.header["sh_size"]}')
            #print("--data follows--")
            #print(f'{section["image"]}')

        syms = self.elf.get_section_by_name(".symtab")
        if syms is not None:
            for sym in syms.iter_symbols():
                sym_type = sym.entry['st_info']['type']
                if sym_type == "STT_NOTYPE" or sym_type == "STT_OBJECT" or sym_type == "STT_FUNC":
                    # This has a location worth memorizing
                    self._addr_to_symbol[sym.entry['st_value']] = sym.name

                    self._symbols[sym.name] = sym

        if self.elf.has_dwarf_info():
            self.verboseprint("Loading debug info from program binary")
            self._dwarf_info = self.elf.get_dwarf_info()
            if not self._dwarf_info.has_debug_info:
                # It was just an exception handler unwind table; no good.
                self._dwarf_info = None
                self.verboseprint("Warning: empty debug info in program binary.")
            if self._dwarf_info:
                types.parseTypeInfo(self._dwarf_info, self.get_arch_conf("int_size"))
        else:
            self.verboseprint("Warning: no debug info in program binary.")

        # Sort the symbols by address and memorize demangled names too.
        self._addr_to_symbol = dict(sorted(self._addr_to_symbol.items()))
        for (addr, name) in self._addr_to_symbol.items():
            self._demangled_to_symbol[binutils.demangle(name)] = name


    def get_section(self, section_name):
        """
            Return a section with the specified name.
        """
        return self._sections[section_name]

    def get_image_bytes(self, start_addr, length):
        """
            Return a `bytes` object containing the "length" in-memory image bytes
            beginning at "start_addr".

            This may retrieve from sections like .text, .data, .bss, etc.
            * This function does not resolve relocations or perform any post-processing on the ELF.
            * This function does not return spans across multiple sections. If start_addr + length
              exceeds the endpoint of the section containing start_addr, it will be truncated to
              the section in question.

            returns None if the start_addr cannot be localized within any section.
        """
        img_section = None
        for (name, section) in self._sections.items():
            if section["addr"] < start_addr and section["addr"] + section["size"] >= start_addr:
                img_section = section
                break

        if img_section is None:
            return None

        #self.verboseprint(f"Image bytes for {start_addr:x} --> {length} in section {img_section['name']}")
        data = img_section["image"]
        start_within_section = start_addr - img_section["addr"]
        img_slice = data[start_within_section : start_within_section + length]
        return img_slice

    def image_for_symbol(self, symname):
        """
            Return the image bytes associated with a symbol (the initialized value of a variable
            in .data, or the machine code within .text for a method)
        """
        #self.verboseprint(f"Getting image for symbol {symname}")
        symdata = self.lookup_sym(symname)
        if symdata is None:
            return None

        return self.get_image_bytes(symdata["addr"], symdata["size"])



    def syms_by_substr(self, substr):
        """
            Return all symbol names that contain the specified substr.
        """
        candidates = []
        all_names = []
        all_names.extend(self._symbols.keys())
        all_names.extend(self._demangled_to_symbol.keys())
        for name in all_names:
            try:
                name.index(substr)
                # If we get here, it's a match.
                candidates.append(name)
            except ValueError:
                pass # Not a match.

        candidates.sort() # Return symbol matches in sorted order.
        out = []
        for sym in candidates:
            if len(out) and out[len(out) - 1] == sym:
                continue # skip duplicate from sorted input list
            out.append(sym)

        return out


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

            if addr + sym['st_size'] > pc:
                return name # Found it.

    def lookup_sym(self, name):
        """
            Given a symbol name (regular or demangled), return a struct
            of information about the symbol.
        """

        try:
            # Is the input a demangled name?
            true_name = self._demangled_to_symbol[name]
        except KeyError:
            # No it is not.
            true_name = name

        try:
            sym = self._symbols[true_name]
        except KeyError:
            return None

        out = {}
        out['name'] = true_name
        out['demangled'] = binutils.demangle(true_name)
        out['size'] = sym.entry['st_size']
        out['addr'] = sym.entry['st_value']

        return out


    ###### Low-level serial interface

    def process_state(self):
        return self._process_state

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

    def wait_for_traces(self):
        """
            When the process is running, listen patiently to the socket for debug_msg() or trace()
            data; print to the screen when it appears.

            If the user wants to break from this, they can ^C and the caller should trap
            KeyboardInterrupt.
        """

        if not self.is_open():
            raise Exception("No debug server connection open")

        while self._process_state != PROCESS_STATE_BREAK:
            line = self._conn.readline().decode("utf-8").strip()
            if len(line) == 0:
                continue
            elif line.startswith(protocol.DBG_RET_PRINT):
                # got a message for the user.
                print(line[1:])
            elif line == protocol.DBG_PAUSE_MSG:
                # Server has informed us that it switched to break mode.
                # (e.g. program-triggered hardcoded breakpoint.)
                print("Paused.")
                self._process_state = PROCESS_STATE_BREAK
                break;
            else:
                # Got a line of ... something but it didn't start with '>'.
                # Either it _is_ for the user and we connected to the socket mid-message,
                # or this client is somehow are in the non-break state while the server IS
                # in the break state and sending a response to some earlier message...
                print(f"Server: [{line}]")


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

        if not self.is_open():
            print("Error: No debug server connection open")
            return None

        # Before sending a command, make sure there is no pent-up data from the server.
        # Discard all service-level data in the buffer and echo any debug statemetns to the console.
        while self._conn.in_waiting > 0:
            line = self._conn.readline().decode("utf-8").strip()
            #print("<-- %s" % line.strip())
            if len(line) == 0:
                continue
            elif line.startswith(protocol.DBG_RET_PRINT):
                # This is debug output for the user to see.
                print(line[1:])


        if type(dbg_cmd) == list:
            dbg_cmd = [str(x) for x in dbg_cmd]
            dbg_cmd = " ".join(dbg_cmd) + "\n"
        elif type(dbg_cmd) != str:
            dbg_cmd = str(dbg_cmd)

        if not dbg_cmd.endswith("\n"):
            dbg_cmd = dbg_cmd + "\n"

        self._conn.write(dbg_cmd.encode("utf-8"))
        #print("--> %s" % dbg_cmd.strip())
        # TODO(aaron): add debug verbosity that enables these i/o lines.

        if result_type == self.RESULT_SILENT:
            return None
        elif result_type == self.RESULT_ONELINE:
            line = None
            while True:
                line = self._conn.readline().decode("utf-8").strip()
                #print("<-- %s" % line.strip())
                if len(line) == 0:
                    continue
                elif line.startswith(protocol.DBG_RET_PRINT):
                    # This is debug output for the user to see.
                    print(line[1:])
                else:
                    break
            return line
        elif result_type == self.RESULT_LIST:
            lines = []
            while True:
                thisline = self._conn.readline().decode("utf-8").strip()
                #print("<-- %s" % thisline.strip())
                if len(thisline) == 0:
                    continue
                elif thisline.startswith(protocol.DBG_RET_PRINT):
                    # Just a message from the debugger/sketch; not part of response.
                    print(thisline[1:])
                elif thisline == "$":
                    break
                else:
                    lines.append(thisline.strip())
            return lines
        else:
            raise RuntimeError("Invalid 'result_type' arg (%d) sent to send_cmd" % result_type)


    ###### Higher-level commands to communicate with server

    def send_break(self):
        break_ok = self.send_cmd(protocol.DBG_OP_BREAK, self.RESULT_ONELINE)
        # Wait up to 1 second for the interrupt to fire to connect the debugger.
        #time.sleep(_break_interrupt_delay)
        # Process state now known as in-break.
        if break_ok == "Paused":
            self._process_state = PROCESS_STATE_BREAK
            print("Paused.")
        else:
            self._process_state = PROCESS_STATE_UNKNOWN
            print("Could not interrupt sketch.")


    def send_continue(self):
        continue_ok = self.send_cmd(protocol.DBG_OP_CONTINUE, self.RESULT_ONELINE)
        if continue_ok == "Continuing":
            self._process_state = PROCESS_STATE_RUNNING
            print("Continuing...")
        else:
            self._process_state = PROCESS_STATE_UNKNOWN
            print("Could not continue sketch.")
            print("Received unexpected response [%s]" % continue_ok)


    def reset_sketch(self):
        self.send_cmd(protocol.DBG_OP_RESET, self._debugger.RESULT_SILENT)
        self._process_state = PROCESS_STATE_UNKNOWN


    def get_registers(self):
        """
            Get snapshot of system registers.
        """
        if len(self._arch) == 0:
            print("Warning: No architecture specified; cannot assign specific registers")
            register_map = [ "general_regs" ]
            num_general_regs = -1
        else:
            register_map = self._arch["register_list_fmt"]
            num_general_regs = self._arch["general_regs"]

        reg_values = self.send_cmd(protocol.DBG_OP_REGISTERS, self.RESULT_LIST)
        registers = {}
        idx = 0
        general_reg_num = 0
        for reg_name in register_map:
            if reg_name == "general_regs":
                # The next 'n' entries are r0, r1, r2...
                # The arch config tells us how many to pull from the list (with the `general_regs`
                # config value).
                if num_general_regs == -1: # Undefined architecture; take all of them.
                    last = len(reg_values)
                else:
                    last = num_general_regs + idx

                start_idx = idx
                for rval in reg_values[start_idx:last]:
                    registers["r" + str(general_reg_num)] = int(rval, base=16)
                    general_reg_num += 1
                    idx += 1
            else:
                # We have a specific named register to assign.
                registers[reg_name] = int(reg_values[idx], base=16)
                idx += 1

        return registers

    def set_sram(self, addr, value, size=1):
        """
            Update data in SRAM on the instance.
        """
        if self._arch["DATA_ADDR_MASK"]:
            # On AVR, ELF file thinks .data starts at 800000h; it actually starts at 0h, aliased
            # with the separate segment containing .text in flash RAM.
            addr = addr & self._arch["DATA_ADDR_MASK"]

        self.send_cmd([protocol.DBG_OP_POKE, size, addr, value], self.RESULT_SILENT)

    def get_sram(self, addr, size=1):
        """
            Return data from SRAM on the instance.
        """

        if self._arch["DATA_ADDR_MASK"]:
            # On AVR, ELF file thinks .data starts at 800000h; it actually starts at 0h, aliased
            # with the separate segment containing .text in flash RAM.
            addr = addr & self._arch["DATA_ADDR_MASK"]

        result = self.send_cmd([protocol.DBG_OP_RAMADDR, size, addr], self.RESULT_ONELINE)
        return int(result, base=16)

    def get_stack_sram(self, offset, size=1):
        """
            Return data from SRAM on the instance, relative to the stack pointer.
        """
        result = self.send_cmd([protocol.DBG_OP_STACKREL, size, offset], self.RESULT_ONELINE)
        return int(result, base=16)

    def get_flash(self, addr, size=1):
        """
            Return data from Flash on the instance.
        """

        result = self.send_cmd([protocol.DBG_OP_FLASHADDR, size, addr], self.RESULT_ONELINE)
        return int(result, base=16)

    def get_stack_snapshot(self, size=16, skip=-1):
        """
            Retrieve the `size` bytes above SP+k (but not past RAMEND),
            where `k` is the number of bytes to skip.

            If `skip` >= 0, k = skip.
            If `skip` == -1, then "auto-skip" the debugger-specific frames.

            @return ($SP, $SP + k + 1, snapshot_array). snapshot_array[0] holds the byte at $SP + 1;
            subsequent entries hold mem at addresses through $SP + size. i.e., the "top of the
            stack" is in array[0] and the bottom of the stack (highest physical addr) at array[n].
        """

        if skip < 0:
            # calculate autoskip amount
            skip = stack.get_stack_autoskip_count(self)

        regs = self.get_registers()
        sp = regs["SP"]
        ramend = self._arch["RAMEND"]
        max_len = ramend - sp + skip + 1
        size = min(size, max_len)
        snapshot = []
        for i in range(sp + skip + 1, sp + skip + 1 + size):
            v = int(self.send_cmd([protocol.DBG_OP_RAMADDR, 1, i], self.RESULT_ONELINE), base=16)
            snapshot.append(v)
        return (sp, sp + skip + 1, snapshot)


    def get_memstats(self):
        """
            Return info about memory map of the CPU and usage.
        """
        lines = self.send_cmd(protocol.DBG_OP_MEMSTATS, self.RESULT_LIST)
        lines = [int(x, base=16) for x in lines]

        mem_map = {}
        mem_map['RAMSTART'] = self._arch["RAMSTART"]
        mem_map['RAMEND'] = self._arch["RAMEND"]
        mem_map['FLASHEND'] = self._arch["FLASHEND"]

        mem_report_fmt = self._arch["mem_list_fmt"]

        if len(lines) == 0:
            return None # Debugger server does not have memstats capability compiled in.
        elif len(lines) != len(mem_report_fmt):
            print("Warning: got response inconsistent with expected report format for arch.")
            return None # Debugger server didn't respond with the right mem_list_fmt..?!

        mem_map.update(list(zip(mem_report_fmt, lines)))
        return mem_map

    def get_backtrace(self, limit=None):
        """
            Retrieve a list of memory addresses representing the top `limit` function calls
            on the call stack. (If limit=None, list all.)

            Return a list of dicts that describe each frame of the stack.
        """
        self.verboseprint(f'Scanning backtrace (limit={limit})')
        ramend = self._arch["RAMEND"]
        ret_addr_size = self._arch["ret_addr_size"] # nr of bytes on stack for a return address.

        # Start by establishing where we are right now.
        regs = self.get_registers()
        pc = regs["PC"]
        sp = regs["SP"]

        frames = []

        # Walk back through the stack to establish the method calls that got us
        # to where we are.
        while sp < ramend and pc != 0 and (limit is None or len(frames) < limit):
            # TODO(aaron): Refactor StackFrame into its own class.
            frame = {}
            frames.append(frame)
            frame['addr'] = pc
            frame['sp'] = sp
            frame['name'] = '???'
            frame['demangled'] = '???'
            frame['frame_size'] = -1
            frame['source_line'] = None
            frame['inline_chain'] = []
            frame['demangled_inline_chain'] = []

            func = self.function_sym_by_pc(pc)
            if func is None:
                print(f"Warning: could not resolve $PC={pc:#04x} to method symbol")
                break # We've hit the limit of traceable methods

            # Look up info about method inlining; the decoded name for $PC may logically
            # be within more methods.
            inline_chain = types.getMethodsForPC(pc)
            print(f"Back with PC {pc:x} and inline chain {inline_chain}")
            frame['inline_chain'] = inline_chain
            frame['demangled_inline_chain'] = [ binutils.demangle(m) for m in inline_chain ]

            frame_size = stack.stack_frame_size_for_method(self, pc, func)

            frame['name'] = func
            frame['demangled'] = binutils.demangle(func)
            frame['frame_size'] = frame_size
            frame['source_line'] = binutils.pc_to_source_line(self.elf_name, pc)

            self.verboseprint(f"function {func} has frame {frame_size}; sp: {sp:04x}, pc: {pc:04x}")

            sp += frame_size # move past the stack frame

            # next 'ret_addr_size' bytes are the return address consumed by RET opcode.
            # pop the bytes off 1-by-1 and consume them as the ret_addr (PC in next fn)
            pc = self.get_return_addr_from_stack(sp + 1)
            sp += ret_addr_size
            self.verboseprint(f"returning to pc {pc:04x}, sp {sp:04x}")

        return frames

    def get_return_addr_from_stack(self, stack_addr):
        """
            Given a stack_addr pointing to the lowest memory address of a
            return address pushed onto the stack, return the associated return address.
        """
        ret_addr_size = self._arch["ret_addr_size"] # nr of bytes on stack for a return address.
        ret_addr = 0
        for i in range(0, ret_addr_size):
            # Because AVR is a little-endian machine, it pushes the low-byte of the return
            # address, then the high byte -- but since the stack grows downward, this means
            # the high byte will actually be at the lower memory address (essentially making
            # return addrs on the stack a single 'big endian' exception to the memory order).
            v = self.get_sram(stack_addr + i, 1)
            ret_addr = (ret_addr << 8) | (v & 0xFF)
        ret_addr = ret_addr << 1 # AVR: LSH all PC values read from memory by 1.
        return ret_addr


    def get_gpio_value(self, pin):
        """
            Retrieve the value (1 or 0) of a GPIO pin on the device.
        """
        if pin < 0 or pin >= self._platform["gpio_pins"]:
            return None

        v = self.send_cmd([protocol.DBG_OP_PORT_IN, pin], self.RESULT_ONELINE)
        if len(v):
            return int(v)
        else:
            return None


    def set_gpio_value(self, pin, val):
        """
            Set a GPIO pin to 1 or 0 based on 'val'.
        """
        if pin < 0 or pin >= self._platform["gpio_pins"]:
            return

        self.send_cmd([protocol.DBG_OP_PORT_OUT, pin, val], self.RESULT_SILENT)

