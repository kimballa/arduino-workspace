# (c) Copyright 2021 Aaron Kimball

from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import CIE

import importlib.resources as resources
import os
import os.path
import queue
from sortedcontainers import SortedDict, SortedList
import threading
import time
import traceback

import arduino_dbg.binutils as binutils
import arduino_dbg.protocol as protocol
import arduino_dbg.serialize as serialize
import arduino_dbg.stack as stack
from arduino_dbg.symbol import Symbol
import arduino_dbg.term as term
from arduino_dbg.term import MsgLevel
import arduino_dbg.types as types

_LOCAL_CONF_FILENAME = os.path.expanduser("~/.arduino_dbg.conf")
_DEFAULT_HISTORY_FILENAME = os.path.expanduser("~/.arduino_dbg_history")

_dbg_conf_keys = [
    "arduino.platform",
    "arduino.arch",
    "dbg.conf.formatversion",
    "dbg.colors",
    "dbg.historyfile",
    'dbg.print_die.offset',
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

# Control codes for verboseprintall() - if this sequence preceeds an int, provides instructions on
# how to format it when printed.
#
# n.b. that this is in-band signalling so theoretically could cause regular data we
# verboseprintall() to be interpreted as a control code, but these are hopefully unlikely to appear
# in such debugging statements.
VDEC = b'\x00\xFF\x0a' # Print base 10
VHEX = b'\x00\xFF\x10' # Print base 16
VHEX2 = b'\x00\xFF\x10\x02' # Print base 16, 0-pad to 2 places
VHEX4 = b'\x00\xFF\x10\x04' # Print base 16, 0-pad to 4 places
VHEX8 = b'\x00\xFF\x10\x08' # Print base 16, 0-pad to 8 places


def _load_conf_module(module_name, resource_name, print_q):
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
        included_map = _load_conf_module(module_name, extra_resource_name, print_q)
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
        print_q.put(("Error loading config profile: %s" % conf_resource_name, MsgLevel.ERR))
        return None

    print_q.put(("Loading config profile: %s; read %d keys" % (conf_resource_name, len(conf)),
        MsgLevel.INFO))
    # conf is now populated with the globals from executing the conf file.
    return conf


class NoServerConnException(Exception):
    pass

class Debugger(object):
    """
        Main debugger state object.
    """

    def __init__(self, elf_name, connection, print_q, arduino_platform=None, force_config=None,
            history_change_hook=None):
        """
        @param elf_name the name of the ELF file holding the binary to debug
        @param connection the Serial connection to device (or pipe connection to local image host)
        @param print_q the queue that connects us to stdout/ConsolePrinter
        @param arduino_platform if not None, overrides config setting for device/arch. Used when
            loading a dump in a debugger to provide same architecture as when dump was captured.
        @param force_config if not None, provides config inputs and suppresses loading from
            user config file. Also suppresses subsequent writes to user config file if settings
            change.
        @param history_change_hook a function to call when the history filename is changed.
        """
        self._print_q = print_q # Data from serial conn to print directly to console.
        self._history_change_hook = history_change_hook

        self._recv_q = None
        self._send_q = None
        # Before we're connected to anything, stay in 'BREAK' state.
        self._process_state = PROCESS_STATE_BREAK
        self._listen_thread = None
        self._alive = False
        self._conn = None

        self.elf_name = elf_name
        self._elf_file_handle = None
        if self.elf_name:
            self.elf_name = os.path.realpath(elf_name)

        self.verboseprint = _silent # verboseprint() method is either _silent() or _verbose_print_all()

        # Set up general user-accessible config.

        # If true, save config changes to file. Generally we save-on-change unless we were given
        # a canned config in our constructor. Then subsequent changes aren't persisted.
        self._do_persist_config_changes = (force_config is None)
        # Load latest config from a dotfile in user's $HOME (unless given a force_config).
        self._init_config_from_file(force_config, arduino_platform)

        self._init_clear_elf_state() # Initialize blank ELF file state (after config load).

        # Load the real debug info from the ELF file.
        self._try_read_elf()

        # Establish connection to the device to debug.
        self.open(connection)

    def _init_clear_elf_state(self):

        # If there's already an open ELF file, close it out.
        if self._elf_file_handle:
            # Close the ELF file we opened at the beginning.
            try:
                self._elf_file_handle.close()
            except e:
                self._print_q.put((f'Error while closing ELF file: {e}', MsgLevel.WARN))

            self._elf_file_handle = None

        self._loaded_debug_info = False
        self._sections = {}
        self._addr_to_symbol = SortedDict()
        self._symbols = SortedDict()
        self._demangled_to_symbol = SortedDict()
        self._dwarf_info = None
        self.elf = None
        self._debug_info_types = types.ParsedDebugInfo(self) # Must create after config load.
        self._cached_frames = None

    def is_debug_info_loaded(self):
        """ Return True if we successfully loaded debug info from an ELF file. """
        return self._loaded_debug_info

    def get_debug_info(self):
        return self._debug_info_types

    def open(self, connection):
        """
            Link to the provided connection.
        """
        if not connection:
            return # Nothing to connect to.

        if self._conn:
            # Close existing conn before opening new one.
            self._close_serial()

        self._conn = connection
        self._print_q.put((f"Opening connection to {connection}...", MsgLevel.INFO))
        self._recv_q = queue.Queue(maxsize=16) # Data from serial conn for debug internal use.
        self._send_q = queue.Queue(maxsize=1) # Data to send out on serial conn.
        self._alive = True
        self._process_state = PROCESS_STATE_UNKNOWN
        self._listen_thread = threading.Thread(target=self._conn_listener,
            name='Debugger serial listener')
        self._listen_thread.start()
        if self.is_open():
            self._print_q.put(("Connected.", MsgLevel.SUCCESS))

    def _close_serial(self):
        """
        Release serial connection resources.
        """
        self._alive = False
        if self._listen_thread:
            self._listen_thread.join()
        self._listen_thread = None

        # Close connection after stopping listener thread.
        if self._conn:
            self._conn.close()
        self._conn = None

        self._recv_q = None
        self._send_q = None

        self._process_state = PROCESS_STATE_BREAK

    def close(self):
        """
            Clean up the debugger and release file resources.
        """
        self._close_serial()

        if self._elf_file_handle:
            # Close the ELF file we opened at the beginning.
            self._elf_file_handle.close()
        self._elf_file_handle = None

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
        conf_map["dbg.conf.formatversion"] = serialize.DBG_CONF_FMT_VERSION
        conf_map["dbg.verbose"] = False
        conf_map["dbg.colors"] = True
        conf_map["dbg.historyfile"] = _DEFAULT_HISTORY_FILENAME

        return conf_map

    def _init_config_from_file(self, force_config=None, arduino_platform=None):
        """
            If the user has a config file (see _LOCAL_CONF_FILENAME) then initialize self._config
            from that.
        """
        defaults = self._set_conf_defaults()
        if force_config is not None:
            # If given a forced input config, initialize our config from there.
            for (key, val) in force_config.items():
                defaults[key] = val
        if arduino_platform:
            # arduino_platform overrides even the provided forced config.
            defaults['arduino.platform'] = arduino_platform

        if os.path.exists(_LOCAL_CONF_FILENAME) and force_config is None:
            # If we have a config file to load, load it -- unless given a force_config,
            # in which case we just stick wtih that.
            config_key = 'config'
            new_conf = serialize.load_config_file(_LOCAL_CONF_FILENAME, config_key, defaults)
        else:
            new_conf = defaults

        self._config = new_conf
        self._platform = {} # Arduino platform-specific config (filled from conf file)
        self._arch = {} # CPU architecture-specific config (filled from conf file)

        # Process all key triggers (except _load_arch(), which will be triggered by
        # _load_platform()).
        self._config_verbose_print()
        self._config_history_file()
        self._load_platform(arduino_platform) # cascade platform def from config, arch def from platform.

        if force_config is None:
            self.verboseprint("Loaded config from file: ", _LOCAL_CONF_FILENAME)
        else:
            self.verboseprint("Used programmatic configuration")
        self.verboseprint("Loaded configuration: ", self._config)



    def _persist_config(self):
        """
            Write the current config out to a file to reload the next time we use the debugger.
        """

        if not self._do_persist_config_changes:
            # We actually do not want to persist changes to file. Do nothing.
            return

        # Don't let user session change this value; we know what serialization version we're
        # writing.
        self._config["dbg.conf.formatversion"] = serialize.DBG_CONF_FMT_VERSION

        config_key = 'config'
        serialize.persist_config_file(_LOCAL_CONF_FILENAME, config_key, self._config)


    def _load_platform(self, arduino_platform=None):
        """
            If the arduino.platform key is set, use it to load the platform-specific config.
            If not None, use the argument arduino_platform instead of the platform value.
        """
        if arduino_platform is not None:
            # Override config.
            platform_name = arduino_platform
            self._config['arduino.platform'] = arduino_platform
        else:
            platform_name = self.get_conf("arduino.platform")

        if not platform_name:
            return
        new_conf = _load_conf_module("arduino_dbg.platforms", platform_name, self._print_q)
        if not new_conf:
            return

        self._platform = new_conf
        self.set_conf("arduino.arch", self._platform["arch"]) # Triggers refresh of arch config.


    def _load_arch(self):
        """
            If the arduino.arch key is set, use it to load the arch-specific config.
        """
        if self._arch:
            old_int_size = self.get_arch_conf("int_size")
            old_addr_size = self.get_arch_conf("ret_addr_size")
        else:
            old_int_size = None
            old_addr_size = None

        arch_name = self.get_conf("arduino.arch")
        if not arch_name:
            return
        new_conf = _load_conf_module("arduino_dbg.arch", arch_name, self._print_q)
        if not new_conf:
            return # Nothing to load.

        self._arch = new_conf

        if old_int_size is not None:
            # If the width of 'int' or pointer addr changes by virtue of changing the architecture
            # profile, the ELF file must be reloaded.
            new_int_size = self.get_arch_conf("int_size")
            new_addr_size = self.get_arch_conf("ret_addr_size")
            if new_int_size != old_int_size or new_addr_size != old_addr_size:
                self._print_q.put((
                    f'Arch changed widths: int={new_int_size}, ptr={new_addr_size}. Reloading ELF...',
                    MsgLevel.WARN))
                self._print_q.join()
                self._try_read_elf()


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
        if key == "dbg.historyfile":
            self._config_history_file()

        self._persist_config() # Write changes to conf file.

    def _make_verbose_print_fn(self):
        """
        Return a 'verboseprint()' method that curries the self._print_q field.
        """

        def _verbose_print_all(*args):
            """
            Verbose printing method that lazily concatenates its arguments rather than requiring
            callers to compute an f'string that might get swallowed by _silent() if verbose printing is
            disabled.
            """

            s = ''
            next_ctrl = None
            for arg in args:
                if isinstance(arg, bytes):
                    if arg == VDEC or arg == VHEX or arg == VHEX2 or arg == VHEX4 or arg == VHEX8:
                        next_ctrl = arg
                        continue
                    else:
                        # Just a byte string to format.
                        s += repr(arg)
                elif next_ctrl is not None and isinstance(arg, int):
                    if next_ctrl == VDEC:
                        s += f'{arg}'
                    elif next_ctrl == VHEX:
                        s += f'{arg:x}'
                    elif next_ctrl == VHEX2:
                        s += f'{arg:02x}'
                    elif next_ctrl == VHEX4:
                        s += f'{arg:04x}'
                    elif next_ctrl == VHEX8:
                        s += f'{arg:08x}'
                    else:
                        # Shouldn't get here with an invalid next_ctrl setting...
                        s += f'<???>{arg}<???>'
                elif isinstance(arg, str):
                    s += arg
                else:
                    s += repr(arg)

                next_ctrl = None

            self._print_q.put((s, MsgLevel.DEBUG))
            self._print_q.join() # Process DEBUG-level messages synchronously, so we can see
                                 # them in proper serialized order w/ the output of the repl.

        return _verbose_print_all


    def _config_verbose_print(self):
        term.set_use_colors(self._config['dbg.colors'])
        if self._config['dbg.verbose']:
            self.verboseprint = self._make_verbose_print_fn()
        else:
            self.verboseprint = _silent

    def _config_history_file(self):
        history_filename = self._config['dbg.historyfile']

        if history_filename is not None:
            # Canonicalize path before storing in conf/file.
            history_filename = os.path.abspath(os.path.expanduser(history_filename))
            self._config['dbg.historyfile'] = history_filename

        if self._history_change_hook is not None:
            # Invoke installed callback (likely installed by repl)
            self._history_change_hook(history_filename)

    def set_history_change_hook(self, history_hook):
        """
        Set a function to invoke whenever the active readline history filename is changed.
        This function will be invoked immediately with the current history filename.
        """
        self._history_change_hook = history_hook
        history_hook(self.get_conf('dbg.historyfile'))

    def get_history_change_hook(self):
        return self._history_change_hook

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

    def get_conf_keys(self):
        """
        Return the set of valid configuration keys for use with 'set'.
        """
        return _dbg_conf_keys

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

    def replace_elf_file(self, elf_filename):
        """
        Close any existing ELF file and reset state; load all new symbols, types, etc.
        from the newly-specified ELF filename.

        If elf_filename is None, just forget what we knew from any prior ELF state.
        """

        assert elf_filename is None or isinstance(elf_filename, str)

        self._init_clear_elf_state() # Wipe any prior state; close handles.

        self.elf_name = elf_filename
        if self.elf_name:
            self.elf_name = os.path.realpath(elf_name)

        self._try_read_elf()


    def _try_read_elf(self):
        """
            Try to read the target ELF file and load debug info. If there is an
            exception in this process, report it to the user, reset our internal
            state, and swallow the exception.
        """
        try:
            self._read_elf()
        except Exception as e:
            self._print_q.put((f'Error while reading ELF file: {e}.', MsgLevel.ERR))
            self._print_q.put((f'Could not load symbols or type information.', MsgLevel.ERR))
            if self.get_conf("dbg.verbose"):
                # Also print stack trace details.
                tb_lines = traceback.extract_tb(e.__traceback__)
                self.verboseprint("".join(traceback.format_list(tb_lines)))
            else:
                self._print_q.put(("For stack trace info, `set dbg.verbose True`", MsgLevel.INFO))

            self._init_clear_elf_state() # Reset ELF info back to 'none'.

    def _read_elf(self):
        """
            Read the target ELF file to load debugging information.
        """
        start_time = time.time()

        if self.elf_name is None:
            self._print_q.put(("No ELF file provided; cannot load symbols", MsgLevel.WARN))
            return

        # Clear any existing ELF-populated state.
        self._init_clear_elf_state()

        # Now we're clear to load the new ELF.
        self._elf_file_handle = open(self.elf_name, 'rb')
        self.elf = ELFFile(self._elf_file_handle)
        self._print_q.put((f"Loading image and symbols from {self.elf_name}", MsgLevel.INFO))

        for elf_sect in self.elf.iter_sections():
            section = {}
            section["name"] = elf_sect.name
            section["size"] = elf_sect.header['sh_size']
            section["offset"] = elf_sect.header['sh_offset']
            section["addr"] = elf_sect.header['sh_addr']
            section["elf"] = elf_sect
            section["image"] = elf_sect.data()[0: section["size"]] # Copy out the section image data.
            self._sections[elf_sect.name] = section

            #self.verboseprint("****************************")
            #self.verboseprint(f'Section {elf_sect.name} has header {elf_sect.header}')
            #self.verboseprint(f'off: {elf_sect.header["sh_offset"]}, size: {elf_sect.header["sh_size"]}')
            #print("--data follows--")
            #print(f'{section["image"]}')

        syms = self.elf.get_section_by_name(".symtab")
        if syms is not None:
            for sym in syms.iter_symbols():
                sym_type = sym.entry['st_info']['type']
                if sym_type == "STT_NOTYPE" or sym_type == "STT_OBJECT" or sym_type == "STT_FUNC":
                    # This has a location worth memorizing
                    dbg_sym = Symbol(sym)
                    self._addr_to_symbol[dbg_sym.addr] = dbg_sym
                    self._symbols[dbg_sym.name] = dbg_sym
                    self._demangled_to_symbol[dbg_sym.demangled] = dbg_sym

        if self.elf.has_dwarf_info():
            self.verboseprint("Loading debug info from program binary")
            self._dwarf_info = self.elf.get_dwarf_info()
            if not self._dwarf_info.has_debug_info:
                # It was just an exception handler unwind table; no good.
                self._dwarf_info = None
                self.verboseprint("Warning: empty debug info in program binary.")
            if self._dwarf_info:
                self._debug_info_types.parseTypeInfo(self._dwarf_info)
                # TODO(aaron): Link the parsed .debug_info / type information to our symbol table.

                # Link .debug_frame unwind info to symbols:
                for cfi_e in self._dwarf_info.CFI_entries():
                    if isinstance(cfi_e, CIE):
                        # This is the Common Information Entry (CIE). Save with the debugger.
                        self._frame_cie = cfi_e
                        continue

                    # We've got an FDE for some method.
                    # Find the method with the relevant $PC
                    frame_sym = self.function_sym_by_pc(cfi_e.header['initial_location'])
                    if frame_sym:
                        frame_sym.setFrameInfo(cfi_e)
                        #self.verboseprint(f"Bound CFI to method {frame_sym.name}.")
                    else:
                        # We have a CFI that claims to start at this $PC, but no method
                        # claims this address.
                        self._print_q.put(
                            (f"Warning: No method for CFI @ $PC={table[0]['pc']:04x}",
                            MsgLevel.WARN))

                    #for row in cfi_e.get_decoded().table:
                    #    row2 = row.copy()
                    #    pc = row2['pc']
                    #    del row2['pc']
                    #    print(f'PC: {pc:04x} {row2}')
                    #print("\n\n")

        else:
            self.verboseprint("Warning: no debug info in program binary.")

        end_time = time.time()
        self.verboseprint(f'Loaded debug information in {1000*(end_time - start_time):0.01f}ms.')
        self._loaded_debug_info = True


    def get_frame_cie(self):
        """
            Return the CIE from .debug_frame. (Default/initial stack frame info for all methods.)
        """
        return self._frame_cie


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

        return self.get_image_bytes(symdata.addr, symdata.size)


    def syms_by_prefix(self, prefix):
        """
            Return all symbol names that start with the specified prefix.
        """
        if prefix is None or len(prefix) == 0:
            nextfix = None # Empty str prefix means return all symbols.
        else:
            # Increment the last char of the string to get the first possible symbol
            # after the matching set.
            last_char = prefix[-1]
            next_char = chr(ord(last_char) + 1)
            nextfix = prefix[0:-1] + next_char

        out = SortedList()
        out.update(self._symbols.irange(prefix, nextfix, inclusive=(True, False)))
        out.update(self._demangled_to_symbol.irange(prefix, nextfix, inclusive=(True, False)))
        return out

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

    def bind_sym_type(self, name, typ):
        """
        Look up a symbol with the specified name ('raw' or demangled) and, if found,
        attach 'typ' to it as its type_info.
        """
        if typ is None or name is None:
            return
        elif self._demangled_to_symbol.get(name):
            self._demangled_to_symbol[name].setTypeInfo(typ)
        elif self._symbols.get(name):
            self._symbols[name].setTypeInfo(typ)

    def function_sym_by_pc(self, pc):
        """
            Given a $PC pointing somewhere within a function body, return the name of
            the symbol for the function.
        """
        for (addr, sym) in self._addr_to_symbol.items():
            if addr > pc:
                # Definitely not this one. Moreover, since _addr_to_symbol is kept
                # and iterated in sorted order, we don't have one to return
                return None

            if sym.elf_sym['st_info']['type'] != "STT_FUNC":
                continue # Not a function

            if addr + sym.elf_sym['st_size'] > pc:
                return sym # Found it.

        return None

    def lookup_sym(self, name):
        """
            Given a symbol name (regular or demangled), return an object
            of type symbol.Symbol with its information.
        """
        return self._demangled_to_symbol.get(name) or self._symbols.get(name)


    ###### Low-level serial interface

    def process_state(self):
        return self._process_state

    def set_process_state(self, state):
        """
        If we know what the process state is, override it with this method.
        """
        self._process_state = state

    def is_open(self):
        return self._conn is not None and self._conn.is_open()

    QUEUE_TIMEOUT = 0.250 # wait up to 250ms to submit new data to a queue

    RESULT_SILENT = 0
    RESULT_ONELINE = 1
    RESULT_LIST = 2

    def __send_msg(self, msgline, response_type):
        """
        Helper method for _conn_listener(), when we need to send a message to the server
        and wait for a response.
        """
        self._conn.write(msgline.encode("utf-8"))
        self._send_q.task_done() # Mark complete as soon as data's affirmatively sent.

        if response_type == Debugger.RESULT_ONELINE:
            line = None
            while self._alive and (line is None or len(line) == 0):
                line = self._conn.readline().decode("utf-8").strip()
                if len(line) == 0:
                    continue
                elif line.startswith(protocol.DBG_RET_PRINT):
                    # Send to the print queue.
                    submitted = False
                    while self._alive and not submitted:
                        try:
                            self._print_q.put((line[1:], MsgLevel.DEVICE), timeout=Debugger.QUEUE_TIMEOUT)
                            submitted = True
                        except queue.Full:
                            continue
                    line = None

            # We have received the response line.
            submitted = False
            #print(f"RECVQ: [{line}]")
            while self._alive and not submitted:
                try:
                    self._recv_q.put(line, timeout=Debugger.QUEUE_TIMEOUT)
                    submitted = True
                except queue.Full:
                    continue
                self._recv_q.join() # Wait for response line to be acknowledged by debugger.
        elif response_type == Debugger.RESULT_LIST:
            while self._alive:
                line = self._conn.readline().decode("utf-8").strip()
                if len(line) == 0:
                    continue
                elif line.startswith(protocol.DBG_RET_PRINT):
                    # Send to the print queue.
                    submitted = False
                    while self._alive and not submitted:
                        try:
                            self._print_q.put((line[1:], MsgLevel.DEVICE), timeout=Debugger.QUEUE_TIMEOUT)
                            submitted = True
                        except queue.Full:
                            continue
                else:
                    # Data response line to forward to consumer
                    submitted = False
                    #print(f"RECVQ: [{line}]")
                    while self._alive and not submitted:
                        try:
                            self._recv_q.put(line, timeout=Debugger.QUEUE_TIMEOUT)
                            submitted = True
                        except queue.Full:
                            continue

                    if line == '$':
                        # That line signaled end of the list.
                        break

            self._recv_q.join() # Wait for response lines to be acknowledged by debugger.
        elif response_type == Debugger.RESULT_SILENT:
            # Nothing further to process in this thread; no response.
            pass
        else:
            self._print_q.put((f'Error: unkonwn response_type {response_type}', MsgLevel.ERR))

    def __flush_recv_q(self):
        """
        Before sending a new command, erase any unconsumed response lines from prior cmd.
        """
        while self._recv_q.qsize() > 0:
            try:
                self._recv_q.get(block=False)
                self._recv_q.task_done()
            except queue.Empty:
                break # Nothing left to grab.

        while self._conn.available():
            self._conn.readline()


    def __acknowledge_pause(self):
        """
        In the conn_listener thread, we received a "Paused" acknowledgement of break request
        from the server. Set our state to confirm that we have received the break stmt.
        """
        self._process_state = PROCESS_STATE_BREAK # Confirm the BREAK status.
        submitted = False
        while self._alive and not submitted:
            try:
                self._print_q.put(("Paused.", MsgLevel.INFO), timeout=Debugger.QUEUE_TIMEOUT)
                submitted = True
            except queue.Full:
                continue

    def _conn_listener(self):
        """
        Run as its own thread; listens for data on the serial connection and also
        sends commands out over the connection.

        As new lines are received, they are either routed to the printer queue
        or the debugger recv queue for processing.
        """
        while self._alive:
            if self._process_state == PROCESS_STATE_BREAK:
                # The device is guaranteed to be in the debugger service. Therefore, we wait
                # for commands to be sent to us from the Debugger to relay to the device.
                self.__flush_recv_q()
                try:
                    (msgline, response_type) = self._send_q.get(timeout=Debugger.QUEUE_TIMEOUT)
                except queue.Empty:
                    continue

                self.__send_msg(msgline, response_type)
            else:
                # Process state is either RUNNING or UNKNOWN.
                # We need to listen for traffic from the device in case it spontaneously
                # emits a debug_print() or trace() message.

                # But first: Send any pending outbound data.
                if self._send_q.qsize() > 0:
                    # Ensure the recv_q is empty; discard any pending lines, since they're
                    # now all unclaimed.
                    self.__flush_recv_q()

                    # Send the outbound line.
                    (msgline, response_type) = self._send_q.get(block=False)
                    self.__send_msg(msgline, response_type)
                    if self._process_state == PROCESS_STATE_BREAK:
                        # We changed process states to BREAK via this msg.
                        # Back to the main loop top, switch into send-biased mode.
                        continue

                # Ideally we would have a way to interrupt this if _send_q is filled
                # while we're waiting on a silent channel, but I don't have a clean way
                # to select() on both at once. Instead we rely on the timeout we specified
                # when opening the connection to bring us back to the top of the loop.
                line = self._conn.readline().decode("utf-8").strip()
                submitted = False

                if len(line) == 0:
                    continue # Didn't get a line; timed out.
                elif line.startswith(protocol.DBG_RET_PRINT):
                    # got a message for the user from debug_msg() or trace().
                    # forward it to the ConsolePrinter.
                    while self._alive and not submitted:
                        try:
                            self._print_q.put((line[1:], MsgLevel.DEVICE), timeout=Debugger.QUEUE_TIMEOUT)
                            submitted = True
                        except queue.Full:
                            continue
                elif line == protocol.DBG_PAUSE_MSG:
                    # Server has informed us that it switched to break mode.
                    # (e.g. program-triggered hardcoded breakpoint.)
                    self.__acknowledge_pause()
                else:
                    # Got a line of something but it didn't start with '>'.
                    # Either it _is_ for the user and we connected to the socket mid-message,
                    # or we received a legitimate response to a query we sent to the server.
                    # Either way, we forward it to the printer, since we don't expect to
                    # receive a response to a command in this state.
                    while self._alive and not submitted:
                        try:
                            self._print_q.put((line, MsgLevel.DEVICE), timeout=Debugger.QUEUE_TIMEOUT)
                            submitted = True
                        except queue.Full:
                            continue

    def send_cmd(self, dbg_cmd, result_type):
        """
            Send a low-level debugger command across the wire and return the results.
            @param dbg_cmd either a formatted command string or list of cmd and arguments.
            @param result_type an integer/enum specifying whether to expect 0, 1, or 'n'
            ($-terminated list) lines in response.
        """

        if not self.is_open():
            raise NoServerConnException("Error: No debug server connection open")

        if self._process_state != PROCESS_STATE_BREAK and dbg_cmd != protocol.DBG_OP_BREAK:
            # We need to be in the BREAK state to send any commands to the service
            # besides the break command itself. Send that first..
            if not self.send_break():
                raise Exception("Could not pause device sketch to send command.")

        if type(dbg_cmd) == list:
            dbg_cmd = [str(x) for x in dbg_cmd]
            dbg_cmd = " ".join(dbg_cmd) + "\n"
        elif type(dbg_cmd) != str:
            dbg_cmd = str(dbg_cmd)

        if not dbg_cmd.endswith("\n"):
            dbg_cmd = dbg_cmd + "\n"

        send_req = (dbg_cmd, result_type)
        self._send_q.put(send_req)  # Tell the communication thread to send the command.
        self._send_q.join()         # Wait for it to be sent.

        if result_type == Debugger.RESULT_SILENT:
            return None
        elif result_type == Debugger.RESULT_ONELINE:
            line = None
            while line is None or len(line) == 0:
                line = self._recv_q.get()
                #print("<-- %s" % line.strip())
                self._recv_q.task_done()

            return line
        elif result_type == Debugger.RESULT_LIST:
            lines = []
            while True:
                thisline = self._recv_q.get()
                self._recv_q.task_done()
                #print("<-- %s" % thisline.strip())
                if len(thisline) == 0:
                    continue
                elif thisline == "$":
                    break
                else:
                    lines.append(thisline.strip())
            return lines
        else:
            raise RuntimeError("Invalid 'result_type' arg (%d) sent to send_cmd" % result_type)


    ###### Higher-level commands to communicate with server

    def send_break(self):
        break_ok = self.send_cmd(protocol.DBG_OP_BREAK, Debugger.RESULT_ONELINE)
        if break_ok == protocol.DBG_PAUSE_MSG:
            self._process_state = PROCESS_STATE_BREAK
            self._print_q.put(("Paused.", MsgLevel.INFO))
            return True
        else:
            self._process_state = PROCESS_STATE_UNKNOWN
            self._print_q.put(("Could not interrupt sketch.", MsgLevel.WARN))
            return False


    def send_continue(self):
        self.clear_frame_cache() # Backtrace is invalidated by continued execution.
        continue_ok = self.send_cmd(protocol.DBG_OP_CONTINUE, Debugger.RESULT_ONELINE)
        if continue_ok == "Continuing":
            self._process_state = PROCESS_STATE_RUNNING
            self._print_q.put(("Continuing...", MsgLevel.INFO))
        else:
            self._process_state = PROCESS_STATE_UNKNOWN
            self._print_q.put(("Could not continue sketch.", MsgLevel.WARN))
            self._print_q.put(("Received unexpected response [%s]" % continue_ok, MsgLevel.WARN))


    def reset_sketch(self):
        self.send_cmd(protocol.DBG_OP_RESET, self._debugger.RESULT_SILENT)
        self._process_state = PROCESS_STATE_UNKNOWN


    def get_registers(self):
        """
            Get snapshot of system registers.
        """
        if len(self._arch) == 0:
            self._print_q.put((
                "Warning: No architecture specified; cannot assign specific registers",
                MsgLevel.WARN))
            register_map = [ "general_regs" ]
            num_general_regs = -1
        else:
            register_map = self._arch["register_list_fmt"]
            num_general_regs = self._arch["general_regs"]

        reg_values = self.send_cmd(protocol.DBG_OP_REGISTERS, Debugger.RESULT_LIST)
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

        if size is None or size < 1:
            self._print_q.put((f"Warning: cannot set memory poke size = {size}; using 1",
                MsgLevel.WARN))
            size = 1

        self.send_cmd([protocol.DBG_OP_POKE, size, addr, value], Debugger.RESULT_SILENT)

    def get_sram(self, addr, size=1):
        """
            Return data from SRAM on the instance.
        """

        if self._arch["DATA_ADDR_MASK"]:
            # On AVR, ELF file thinks .data starts at 800000h; it actually starts at 0h, aliased
            # with the separate segment containing .text in flash RAM.
            addr = addr & self._arch["DATA_ADDR_MASK"]

        if size is None or size < 1:
            self._print_q.put((f"Warning: cannot set memory fetch size = {size}; using 1",
                MsgLevel.WARN))
            size = 1

        result = self.send_cmd([protocol.DBG_OP_RAMADDR, size, addr], Debugger.RESULT_ONELINE)
        return int(result, base=16)

    def get_stack_sram(self, offset, size=1):
        """
            Return data from SRAM on the instance, relative to the stack pointer.
        """
        result = self.send_cmd([protocol.DBG_OP_STACKREL, size, offset], Debugger.RESULT_ONELINE)
        return int(result, base=16)

    def get_flash(self, addr, size=1):
        """
            Return data from Flash on the instance.
        """

        result = self.send_cmd([protocol.DBG_OP_FLASHADDR, size, addr], Debugger.RESULT_ONELINE)
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
            v = int(self.send_cmd([protocol.DBG_OP_RAMADDR, 1, i], Debugger.RESULT_ONELINE), base=16)
            snapshot.append(v)
        return (sp, sp + skip + 1, snapshot)


    def get_memstats(self):
        """
            Return info about memory map of the CPU and usage.
        """
        lines = self.send_cmd(protocol.DBG_OP_MEMSTATS, Debugger.RESULT_LIST)
        lines = [int(x, base=16) for x in lines]

        mem_map = {}
        mem_map['RAMSTART'] = self._arch["RAMSTART"]
        mem_map['RAMEND'] = self._arch["RAMEND"]
        mem_map['FLASHEND'] = self._arch["FLASHEND"]

        mem_report_fmt = self._arch["mem_list_fmt"]

        if len(lines) == 0:
            return None # Debugger server does not have memstats capability compiled in.
        elif len(lines) != len(mem_report_fmt):
            self._print_q.put((
                "Warning: got response inconsistent with expected report format for arch.",
                MsgLevel.WARN))
            return None # Debugger server didn't respond with the right mem_list_fmt..?!

        mem_map.update(list(zip(mem_report_fmt, lines)))
        return mem_map

    def get_gpio_value(self, pin):
        """
            Retrieve the value (1 or 0) of a GPIO pin on the device.
        """
        if pin < 0 or pin >= self._platform["gpio_pins"]:
            return None

        v = self.send_cmd([protocol.DBG_OP_PORT_IN, pin], Debugger.RESULT_ONELINE)
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

        self.send_cmd([protocol.DBG_OP_PORT_OUT, pin, val], Debugger.RESULT_SILENT)

    ######### Highest-level debugging functions built on top of low-level capabilities

    def get_backtrace(self, limit=None):
        """
            Retrieve a list of memory addresses representing the top `limit` function calls
            on the call stack. (If limit=None, list all.)

            Return a list of dicts that describe each frame of the stack.
        """
        if self._cached_frames:
            # We already have a backtrace.
            return self._cached_frames[0:limit]

        self.verboseprint('Scanning backtrace')
        ramend = self._arch["RAMEND"]
        ret_addr_size = self._arch["ret_addr_size"] # nr of bytes on stack for a return address.

        # Start by establishing where we are right now.
        regs = self.get_registers()
        pc = regs["PC"]
        sp = regs["SP"]

        frames = []

        # Walk back through the stack to establish the method calls that got us
        # to where we are. If we didn't have a cached backtrace, get the entire thing (ignore
        # limit).
        while sp < ramend and pc != 0:
            frame = stack.CallFrame(self, pc, sp)
            frames.append(frame)

            if frame.name is None:
                break # We've hit the limit of traceable methods

            self.verboseprint(f"function {frame.name} has frame {frame.frame_size}; " +
                f"sp: {sp:04x}, pc: {pc:04x}")

            sp += frame.frame_size # move past the stack frame

            # next 'ret_addr_size' bytes are the return address consumed by RET opcode.
            # pop the bytes off 1-by-1 and consume them as the ret_addr (PC in next fn)
            pc = self.get_return_addr_from_stack(sp + 1)
            sp += ret_addr_size
            self.verboseprint(f"returning to pc {pc:04x}, sp {sp:04x}")

        self._cached_frames = frames # Cache this backtrace for further lookups.
        return frames[0:limit]

    def clear_frame_cache(self):
        """ Clear cached backtrace information. """
        self._cached_frames = None

    def get_frame_regs(self, frame_num):
        """
        Return register snapshot as of the specified frame.
        """

        frames = self.get_backtrace(limit=frame_num+1)
        if len(frames) <= frame_num:
            # Cannot find a frame that deep in the backtrace.
            return None

        # start with the current regs.
        regs = self.get_registers()

        # frame[i].unwind_registers() will reverse the register operations within that
        # frame, giving the register state for frame i+1. So if frame_num=0, this loop
        # doesn't run and the real registers are the current registers. Otherwise, we
        # apply this reversal function on all frames prior to the target frame.
        for i in range(0, frame_num):
            regs = frames[i].unwind_registers(regs)

        return regs

    def get_frame_vars(self, frame_num):
        """
            Return information about variables in scope at the $PC within a stack frame.

            Returns a list of types.MethodType and types.LexicalScope objects that enclose
            the $PC at the requested stack frame, or None if there is no such frame.
        """
        frame_regs = self.get_frame_regs(frame_num)
        if frame_regs is None:
            return None # No such frame.

        pc = frame_regs["PC"]
        return self._debug_info_types.getScopesForPC(pc, include_global=False)


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


