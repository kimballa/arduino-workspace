# (c) Copyright 2021 Aaron Kimball

from elftools.elf.elffile import ELFFile
import importlib.resources as resources
import os
import serial
import time

import arduino_dbg.binutils as binutils
import arduino_dbg.protocol as protocol

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
    try:
        exec(conf_text, conf, conf)
        del conf["__builtins__"] # Pull python internals from gloabls map we're using as config.
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

        self._persist_config() # Write changes to conf file.

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

    def _read_elf(self):
        """
            Read the target ELF file to load debugging information.
        """
        if self.elf_name is None:
            print("No ELF file provided; cannot load symbols")
            return

        with open(self.elf_name, 'rb') as f:
            elf = ELFFile(f)
            print(f"Loading image and symbols from {self.elf_name}")

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

                        self._symbols[sym.name] = sym


                #print("*** Symbols (.symtab)")
                #for sym in syms.iter_symbols():
                #    print("%s: %s" % (sym.name, sym.entry))

        # Sort the symbols by address and memorize demangled names too.
        self._addr_to_symbol = dict(sorted(self._addr_to_symbol.items()))
        for (addr, name) in self._addr_to_symbol.items():
            self._demangled_to_symbol[binutils.demangle(name)] = name


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

    def get_flash(self, addr, size=1):
        """
            Return data from Flash on the instance.
        """

        result = self.send_cmd([protocol.DBG_OP_FLASHADDR, size, addr], self.RESULT_ONELINE)
        return int(result, base=16)

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

    def get_backtrace(self):
        """
            Retrieve a list of memory addresses representing the call stack.

            Return a list of dicts that describe each frame of the stack.
        """

        # Step 1 is to acquire the backtrace data from the client. This returns a list of
        # alternating pairs -- call-site, start-of-method, call-site... *
        # If interrupted by BREAK(), the top-most call-site item will be NULL since __dbg_break()
        # already captured its caller before halting.
        #
        # * technically it's the PC right after the call; the /return/ site addr.
        #
        # e.g if main() calls foo() calls bar(), we receive entries like:
        # 4B <location in bar() where debugger interrupted>
        # 3A <top of bar()>
        # 3B <location in foo() that called bar>
        # 2A <top of foo()>
        # 2B <location in main() that called foo>
        # 1A <top of main()>
        # 1B <point in .init that kicked off main()>
        #
        # This list is enumerated from the server top-to-bottom. `lines[0]` is 4B, `lines[n]` is 1B.

        lines = self.send_cmd(protocol.DBG_OP_CALLSTACK, self.RESULT_LIST)

        addrs = [int(line, 16) for line in lines]
        funcs = [self.function_sym_by_pc(addr) for addr in addrs]

        # Once captured, we need to process it as follows, to get a useful call stack:
        #
        # 1) throw away any nulls.
        # 2) resolve all locations to the method they're in.
        # 2) if nB and (n-1)A are in the same method, drop the '(n-1)A' containing
        #    top-of-method; call site within that method is better info to display.
        # 3) otoh, if nB and (n-1)A are in *different* methods then there was at least
        #    one call to a non-instrumented function in the middle; we may have missed
        #    an arbitrary amount of stack frames in the middle, so add a '...???...' flag
        # 4) Process intra-method addresses to source file & line number
        #
        # The result is the best backtrace we can reconstruct with the methods we have instrumented,
        # indicating PC within method where available, or at least what method(s) are on the stack.
        # We also have detected and marked any incomplete gaps in the call stack record.

        i = 0
        is_call_site = True # first elem of the list is a call site
        call_site_elems = []
        while i < len(addrs):
            addr = addrs[i]
            func = funcs[i]
            do_delete = False

            if addr == 0 or addr is None:
                do_delete = True
                del addrs[i]
                del funcs[i]
                # keep 'i' where it is to get the next item.
                is_call_site = not is_call_site # next item has different call-site-ness.
                # do not append to call_site_elems since we deleted the current list entry.
            elif is_call_site and i < len(funcs) - 1 and func == funcs[i + 1]:
                # remove top-of-method, when we have intra-method PC
                del addrs[i + 1]
                del funcs[i + 1]

                call_site_elems.append(True)

                # increment 'i' to get the next item.
                # but note that next item has same call-site-ness as this one
                i += 1
            elif is_call_site and i < len(funcs) - 1 and func != funcs[i + 1]:
                # We've found a gap in the call stack; make a note.
                addrs.insert(i + 1, 0x0)
                funcs.insert(i + 1, "...???...")

                call_site_elems.append(True)  # This item is a call site.
                call_site_elems.append(False) # the '???' is not.

                i += 2 # increment 'i' an extra time to hop over the tombstone record.
                is_call_site = not is_call_site
            else:
                call_site_elems.append(is_call_site)
                i += 1
                is_call_site = not is_call_site

        demangled = [binutils.demangle(func) for func in funcs]

        out = []
        for i in range(0, len(addrs)):
            frame = {}
            frame["addr"] = addrs[i]
            frame["name"] = funcs[i]
            frame["demangled"] = demangled[i]
            if call_site_elems[i]:
                frame["source_line"] = binutils.pc_to_source_line(self.elf_name, addrs[i])
            else:
                frame["source_line"] = None

            out.append(frame)

        return out


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

