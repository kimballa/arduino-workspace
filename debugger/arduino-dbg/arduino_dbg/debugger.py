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

import arduino_dbg.breakpoint as breakpoint
import arduino_dbg.protocol as protocol
import arduino_dbg.serialize as serialize
import arduino_dbg.stack as stack
from arduino_dbg.symbol import Symbol
import arduino_dbg.term as term
from arduino_dbg.term import MsgLevel
import arduino_dbg.types as types

_LOCAL_CONF_FILENAME = os.path.expanduser("~/.arduino_dbg.conf")
_DEFAULT_HISTORY_FILENAME = os.path.expanduser("~/.arduino_dbg_history")

_DEFAULT_MAX_CONN_RETRIES = 3
_DEFAULT_MAX_POLL_RETRIES = 20
_DEFAULT_POLL_TIMEOUT = 100  # milliseconds

_dbg_conf_keys = [
    "arduino.platform",
    "arduino.arch",
    "dbg.colors",
    "dbg.conf.formatversion",
    "dbg.conn.retries",
    "dbg.historyfile",
    "dbg.poll.retry",    # Attempt to listen how many times in __wait_response() ?
    "dbg.poll.timeout",  # When listening to recv_q in __wait_response(), wait how long?
    'dbg.print_die.offset',
    "dbg.verbose",
]


class ProcessState:
    """
    When we connect to the device, which state are we in?

    Depending on the process state, the connection listener thread is biased to either
    passively listen for dbgprint() and trace() messages from the device, or expect
    command--response interactions to originate from the local client.
    """

    UNKNOWN = 0  # Don't know if sketch is running or note. Bias to assuming it is running.
    RUNNING = 1  # The sketch is definitely running.
    BREAK = 2    # The sketch is definitely parked at a breakpoint / interrupt in the dbg service.


class ConnRestart:
    """
    If the connection suddenly disconnects/errors within the _conn_listener thread,
    whose responsibility is it to attempt to restart the connection?

    If within a command--response scenario, the cilent should handle it; we cannot trust
    that all the intervening data will make it to the client, so it may wait forever for
    a response unless it just gets the exception and understands its command to have failed.

    If we're just passively listening for debug logging info coming off the device, the
    _conn_listener should attempt to restart itself, as the client will likely be waiting
    for user 'readline' input and won't be in a position to issue the restart command
    in a timely fashion.

    * We use the Debugger._restart_responsibility = ConnRestart.CLIENT state if _conn_listener()
      is in __send_msg() or __flush_recv_q().
    * At all other times, we set _restart_responsibility = ConnRestart.INTERNAL.
    """
    INTERNAL = 0
    CLIENT = 1


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
VDEC = b'\x00\xFF\x0a'  # Print base 10
VHEX = b'\x00\xFF\x10'  # Print base 16
VHEX2 = b'\x00\xFF\x10\x02'  # Print base 16, 0-pad to 2 places
VHEX4 = b'\x00\xFF\x10\x04'  # Print base 16, 0-pad to 4 places
VHEX8 = b'\x00\xFF\x10\x08'  # Print base 16, 0-pad to 8 places


def _load_conf_module(module_name, resource_name, print_q):
    """
        Open a resource (file) within a module with a '.conf' extension and treat it like python
        code; execute it in a sheltered environment and return the processed globals as a k-v map.

        We use this for Arduino Platform and cpu architecture (Arch) definitions.
    """
    if resource_name is None or len(resource_name) == 0:
        return None  # Nothing to load.

    conf_resource_name = resource_name.strip() + ".conf"
    conf_text = resources.read_text(module_name, conf_resource_name)
    conf = {}  # Create an empty environment in which to run the config code.

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

    conf['include'] = _include_fn  # Give the 'include' function to the scope.
    try:
        exec(conf_text, conf, conf)
        del conf["__builtins__"]  # Pull python internals from gloabls map we're using as config.
        del conf["include"]  # Pull out the include() function we provided.

        # Remove any "__private" items.
        to_delete = []
        for (k, v) in conf.items():
            if isinstance(k, str) and k.startswith("__"):
                to_delete.append(k)
        for key in to_delete:
            del conf[key]

    except Exception:
        # Error parsing/executing conf; return empty result.
        print_q.put(("Error loading config profile: %s" % conf_resource_name, MsgLevel.ERR))
        return None

    print_q.put(("Loading config profile: %s; read %d keys" % (conf_resource_name, len(conf)),
                MsgLevel.INFO))
    # conf is now populated with the globals from executing the conf file.
    return conf


class DebuggerIOError(Exception):
    """
    Base class for I/O errors that may occur communicating cmds to the device
    debugger service.
    """
    pass


class NoServerConnException(DebuggerIOError):
    """ We're not actually connected in the first place. """
    pass


class DisconnectedException(DebuggerIOError):
    """ Disconnected during the operation """
    pass


class InvalidConnStateException(DebuggerIOError):
    """ We tried to interrupt the device to send the command but could not. """
    pass


class Debugger(object):
    """
        Main debugger state object.
    """

    def __init__(self, elf_name, connection, print_q, arduino_platform=None, force_config=None,
                 history_change_hook=None, is_locked=False):
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
        self._print_q = print_q  # Data from serial conn to print directly to console.
        self._history_change_hook = history_change_hook

        self._recv_q = None       # Main debugger client receives responses from server via this q.
        self._send_q = None       # Client(s) may enqueue comms to the server (commands) via this q.

        # A thread wishing to send on the send_q must acquire the 'submit lock' first. You must
        # acquire this *before* calling any methods that may submit commands, as a compound method
        # may need to make multiple submissions.
        self._submit_lock = threading.Lock()
        self._cmd_event = threading.Event()  # Event to signal a client is waiting to acquire lock.
        if is_locked:
            self._submit_lock.acquire()  # Start with lock owned by caller.

        # Before we're connected to anything, stay in 'BREAK' state.
        self._process_state = ProcessState.BREAK
        self._listen_thread = None      # This thread listens for input from the device (and relays to
                                        # the print q or recv q depending on state). It also listens
                                        # for commands on the send q and dispatches those, putting the
                                        # response on the recv q.

        self._alive = False             # True if the listen thread should stay alive.
        self._disconnect_err = False    # Set True if the listen thread died due to TTY disconnect.
        # Should the listener thread attempt to reestablish a disconnected TTY connection by itself
        # (INTERNAL) or is the client responsible for initiating reconnection / recovery?
        self._restart_responsibility = ConnRestart.INTERNAL
        self._conn = None               # The serial connection to the device or mock device for dump
                                        # debugging. See impls in arduino_dbg.io package.

        # The filename of the sketch image.
        self.elf_name = elf_name
        self._elf_file_handle = None
        if self.elf_name:
            self.elf_name = os.path.realpath(self.elf_name)

        self.verboseprint = _silent  # verboseprint() method is either _silent() or _verbose_print_all()

        # Set up general user-accessible config.

        # If true, save config changes to file. Generally we save-on-change unless we were given
        # a canned config in our constructor. Then subsequent changes aren't persisted.
        self._do_persist_config_changes = (force_config is None)
        # Load latest config from a dotfile in user's $HOME (unless given a force_config).
        self._init_config_from_file(force_config, arduino_platform)

        self._init_clear_elf_state()  # Initialize blank ELF file state (after config load).

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
            except Exception as e:
                self.msg_q(MsgLevel.WARN, f'Error while closing ELF file: {e}')

            self._elf_file_handle = None

        self._loaded_debug_info = False
        self._sections = {}
        self._addr_to_symbol = SortedDict()
        self._symbols = SortedDict()
        self._demangled_to_symbol = SortedDict()
        self._dwarf_info = None
        self.elf = None
        self._debug_info_types = types.ParsedDebugInfo(self)  # Must create after config load.
        self._breakpoints = breakpoint.BreakpointDatabase(self)
        self._cached_frames = None
        self._frame_cache_complete = False

    def msg_q(self, color, *args):
        """
        Enqueue a msg for printing to the console. Adds the stringified message and color/priority
        level to the print queue.

        @param color either a term color string (term.COLOR_BOLD) or MsgLevel enum
        @param args a set of arguments to stringify and concatenate.
        """
        def _str_fn(x):
            if isinstance(x, str):
                return x
            else:
                return repr(x)

        msg_str = "".join(list(map(_str_fn, args)))
        self._print_q.put((msg_str, color))


    def is_debug_info_loaded(self):
        """ Return True if we successfully loaded debug info from an ELF file. """
        return self._loaded_debug_info

    def get_debug_info(self):
        return self._debug_info_types

    def breakpoints(self):
        return self._breakpoints

    def _get_max_retries(self):
        if self._conn is None:
            return 0  # No connection to retry.

        conn_retries = self._conn.max_retries()
        config_retries = self.get_conf('dbg.conn.retries')
        if conn_retries is None:
            # No connection-imposed limit. Use configured limit.
            return max(0, config_retries)
        else:
            return max(0, min(config_retries, conn_retries))

    def reconnect(self):
        """
        If we already have a connection and it errored out, re-attempt connection, up to
        a maximum number of retries.

        @return True if the reconnect was successful, False otherwise.
        """
        if self._conn is None:
            # Nothing to work with here.
            self.msg_q(MsgLevel.ERR, "No connection to reconnect")
            return False

        if self._listen_thread and self._listen_thread.ident != threading.get_ident():
            # Wait for existing thread to exit -- unless this is invoked within that thread.
            # (In which case, it's already on the way out and knows it.)
            self._alive = False
            self._listen_thread.join()
            self._listen_thread = None

        max_retries = self._get_max_retries()
        for i in range(0, max_retries):
            try:
                self.msg_q(MsgLevel.INFO, f"Reconnecting... (Attempt {i+1} of {max_retries})")
                if i == 0:
                    # Start reconnection process by waiting generously for USB-serial to be detected by OS.
                    time.sleep(3)
                else:
                    # More modest wait between subsequent retries.
                    time.sleep(2)

                # Attempt reconnection.
                self._conn.reopen()
                # Got the connection restarted -- start a new conn_listener thread.
                self.__start_conn_listener()
                return True  # success!
            except Exception:
                # Didn't work this retry. Wait a bit and try again.
                pass

        # We have tried the maximum number of tries we're allowed. Completely give up.
        self._alive = False  # Make sure nothing's lingering around.
        self.msg_q(MsgLevel.ERR, "Could not reestablish connection")
        return False  # Couldn't make it work.


    def open(self, connection):
        """
            Link to the provided connection.
        """
        if not connection:
            self.msg_q(MsgLevel.WARN, "No serial port specified; cannot connect to device to debug.")
            self.msg_q(MsgLevel.INFO,
                       ("Use `open </dev/ttyname>` to connect to a serial port, or `load <filename>` "
                        "to load a dump file."))
            return  # Nothing to connect to.

        if self._conn:
            # Close existing conn before opening new one.
            self._close_serial()

        self._conn = connection
        self.__start_conn_listener()

    def __start_conn_listener(self):
        """
        Set up internal listener thread & associated state after connection is established.
        """
        self.msg_q(MsgLevel.INFO, f"Opening connection to {self._conn}...")
        self._recv_q = queue.Queue(maxsize=16)  # Data from serial conn for debug internal use.
        self._send_q = queue.Queue(maxsize=1)   # Data to send out on serial conn.
        self._alive = True
        self._disconnect_err = False
        self._process_state = ProcessState.UNKNOWN
        self._restart_responsibility = ConnRestart.INTERNAL
        self._listen_thread = threading.Thread(target=self._conn_listener,
                                               name='Debugger serial listener')
        self._listen_thread.start()
        if self.is_open():
            self.msg_q(MsgLevel.SUCCESS, "Connected.")

    def _close_serial(self):
        """
        Release serial connection resources.
        """
        self._alive = False
        if self._listen_thread and self._listen_thread.ident != threading.get_ident():
            # Wait for existing thread to exit -- unless this is invoked within that thread.
            # (In which case, it's already on the way out and knows it.)
            self._listen_thread.join()
        self._listen_thread = None

        # Close connection after stopping listener thread.
        if self._conn:
            self._conn.close()
        self._conn = None
        self._disconnect_err = False

        self._recv_q = None
        self._send_q = None

        self._process_state = ProcessState.BREAK

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
        conf_map["dbg.conn.retries"] = _DEFAULT_MAX_CONN_RETRIES
        conf_map["dbg.poll.retry"] = _DEFAULT_MAX_POLL_RETRIES
        conf_map["dbg.poll.timeout"] = _DEFAULT_POLL_TIMEOUT

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
            new_conf = serialize.load_config_file(self._print_q, _LOCAL_CONF_FILENAME,
                                                  config_key, defaults)
        else:
            new_conf = defaults

        self._config = new_conf
        self._platform = {}  # Arduino platform-specific config (filled from conf file)
        self._arch = {}  # CPU architecture-specific config (filled from conf file)

        # Process all key triggers (except _load_arch(), which will be triggered by
        # _load_platform()).
        self._config_verbose_print()
        self._config_history_file()
        self._load_platform(arduino_platform)  # cascade platform def from config, arch def from platform.

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
        self.set_conf("arduino.arch", self._platform["arch"])  # Triggers refresh of arch config.


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
            return  # Nothing to load.

        self._arch = new_conf

        if old_int_size is not None:
            # If the width of 'int' or pointer addr changes by virtue of changing the architecture
            # profile, the ELF file must be reloaded.
            new_int_size = self.get_arch_conf("int_size")
            new_addr_size = self.get_arch_conf("ret_addr_size")
            if new_int_size != old_int_size or new_addr_size != old_addr_size:
                self.msg_q(MsgLevel.WARN,
                           f'Arch changed widths: int={new_int_size}, ptr={new_addr_size}. Reloading ELF...')
                self._try_read_elf()

        # Clear cached architecture parameters in DWARFExprMachine
        import arduino_dbg.eval_location as el
        el.DWARFExprMachine.hard_reset_state()
        el.DWARFExprMachine([], {}, self)


    def set_conf(self, key, val):
        """
        Set a key-value pair in the configuration map.
        Then process any triggers associated with that key.
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

        self._persist_config()  # Write changes to conf file.

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

            self.msg_q(MsgLevel.DEBUG, s)

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
        Return all user-configurable configuration key-val pairs.
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

        self._init_clear_elf_state()  # Wipe any prior state; close handles.

        self.elf_name = elf_filename
        if self.elf_name:
            self.elf_name = os.path.realpath(self.elf_name)

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
            self.msg_q(MsgLevel.ERR, f'Error while reading ELF file: {e}.')
            self.msg_q(MsgLevel.ERR, f'Could not load symbols or type information.')
            if self.get_conf("dbg.verbose"):
                # Also print stack trace details.
                tb_lines = traceback.extract_tb(e.__traceback__)
                self.verboseprint("".join(traceback.format_list(tb_lines)))
            else:
                self.msg_q(MsgLevel.INFO, "For stack trace info, `set dbg.verbose True`")

            self._init_clear_elf_state()  # Reset ELF info back to 'none'.

    def _read_elf(self):
        """
        Read the target ELF file to load debugging information.
        """
        start_time = time.time()

        if self.elf_name is None:
            self.msg_q(MsgLevel.WARN, "No ELF file provided; cannot load symbols.")
            self.msg_q(MsgLevel.INFO, "Use `read <filename.elf>` to load a program image.")
            return

        # Clear any existing ELF-populated state.
        self._init_clear_elf_state()

        # Now we're clear to load the new ELF.
        self._elf_file_handle = open(self.elf_name, 'rb')
        self.elf = ELFFile(self._elf_file_handle)
        self.msg_q(MsgLevel.INFO, f"Loading image and symbols from {self.elf_name}")

        for elf_sect in self.elf.iter_sections():
            section = {}
            section["name"] = elf_sect.name
            section["size"] = elf_sect.header['sh_size']
            section["offset"] = elf_sect.header['sh_offset']
            section["addr"] = elf_sect.header['sh_addr']
            section["elf"] = elf_sect
            section["image"] = elf_sect.data()[0: section["size"]]  # Copy out the section image data.
            self._sections[elf_sect.name] = section

            # self.verboseprint("****************************")
            # self.verboseprint(f'Section {elf_sect.name} has header {elf_sect.header}')
            # self.verboseprint(f'off: {elf_sect.header["sh_offset"]}, size: {elf_sect.header["sh_size"]}')
            # print("--data follows--")
            # print(f'{section["image"]}')

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
                        # self.verboseprint(f"Bound CFI to method {frame_sym.name}.")
                    else:
                        # We have a CFI that claims to start at this $PC, but no method
                        # claims this address.
                        missing_pc = cfi_e.header['initial_location']
                        self.msg_q(MsgLevel.WARN, f"Warning: No method for CFI @ $PC={missing_pc:04x}")

                    # for row in cfi_e.get_decoded().table:
                    #     row2 = row.copy()
                    #     pc = row2['pc']
                    #     del row2['pc']
                    #     self.msg_q(MsgLevel.DEBUG, f'PC: {pc:04x} {row2}')
                    # self.msg_q(MsgLevel.DEBUG, "\n\n")

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

        # self.verboseprint(f"Image bytes for {start_addr:x} --> {length} in section {img_section['name']}")
        data = img_section["image"]
        start_within_section = start_addr - img_section["addr"]
        img_slice = data[start_within_section: start_within_section + length]
        return img_slice

    def image_for_symbol(self, symname):
        """
        Return the image bytes associated with a symbol (the initialized value of a variable
        in .data, or the machine code within .text for a method)
        """
        # self.verboseprint(f"Getting image for symbol {symname}")
        symdata = self.lookup_sym(symname)
        if symdata is None:
            return None

        return self.get_image_bytes(symdata.addr, symdata.size)


    def syms_by_prefix(self, prefix):
        """
        Return all symbol names that start with the specified prefix.
        """
        if prefix is None or len(prefix) == 0:
            nextfix = None  # Empty str prefix means return all symbols.
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
                pass  # Not a match.

        candidates.sort()  # Return symbol matches in sorted order.
        out = []
        for sym in candidates:
            if len(out) and out[len(out) - 1] == sym:
                continue  # skip duplicate from sorted input list
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
                continue  # Not a function

            if addr + sym.elf_sym['st_size'] > pc:
                return sym  # Found it.

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

    def get_cmd_lock(self, blocking=True, timeout=-1):
        """
        Acquire the lock that gives this thread the right to send commands on the send_q.

        A Repl should call this method _before_ doing work that may call other methods
        like send_break() or get_backtrace(), etc.

        You should release the lock (with `release_cmd_lock()`) only after completing the end-to-end
        interaction with the server (which may be multiple command--response elements).
        """
        self._cmd_event.set()  # Tell the _conn_listener we want the lock, don't hog it.
        acquired = self._submit_lock.acquire(blocking, timeout)
        if acquired:
            self._cmd_event.clear()
        return acquired

    def release_cmd_lock(self):
        """ Release the send_q lock. """
        self._submit_lock.release()

    QUEUE_TIMEOUT = 0.100  # wait up to 100ms to submit new data to a queue

    RESULT_SILENT = 0
    RESULT_ONELINE = 1
    RESULT_LIST = 2

    def __send_msg(self, msgline, response_type):
        """
        Helper method for _conn_listener(), when we need to send a message to the server
        and wait for a response.
        """
        self._conn.write(msgline.encode("utf-8"))
        if response_type == Debugger.RESULT_SILENT:
            # Client isn't waiting for a response. Immediately reassert responsibility
            # for connection restart before acknowledging the send-complete and allowing
            # the client to resume their thread.
            self._restart_responsibility = ConnRestart.INTERNAL
        self._send_q.task_done()  # Mark complete as soon as data's affirmatively sent.

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
            # We reassert responsibility for reconnect after finishing requested conn I/O,
            # but before allowing the client to continue by handing them back the response line.
            self._restart_responsibility = ConnRestart.INTERNAL
            # print(f"RECVQ: [{line}]")
            while self._alive and not submitted:
                try:
                    self._recv_q.put(line, timeout=Debugger.QUEUE_TIMEOUT)
                    submitted = True
                except queue.Full:
                    continue

                self._recv_q.join()  # Wait for response line to be acknowledged by debugger.
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
                    if line == '$':
                        # end of list and end of requested conn I/O.
                        # We reassert responsibility for reconnect after finishing requested conn I/O,
                        # but before allowing the client to continue by handing them back the response line.
                        self._restart_responsibility = ConnRestart.INTERNAL
                    submitted = False
                    # print(f"RECVQ: [{line}]")
                    while self._alive and not submitted:
                        try:
                            self._recv_q.put(line, timeout=Debugger.QUEUE_TIMEOUT)
                            submitted = True
                        except queue.Full:
                            continue

                    if line == '$':
                        # That line signaled end of the list.
                        break

            self._recv_q.join()  # Wait for response lines to be acknowledged by debugger.
        elif response_type == Debugger.RESULT_SILENT:
            # Nothing further to process in this thread; no response.
            pass
        else:
            self.msg_q(MsgLevel.ERR, f'Error: unkonwn response_type {response_type}')

    def __flush_recv_q(self):
        """
        Before sending a new command, erase any unconsumed response lines from prior cmd.
        """
        while self._recv_q.qsize() > 0:
            try:
                self._recv_q.get(block=False)
                self._recv_q.task_done()
            except queue.Empty:
                break  # Nothing left to grab.

        while self._conn.available():
            self._conn.readline()


    def __acknowledge_pause(self, pause_notification):
        """
        In the conn_listener thread, we received a "Paused" acknowledgement of break request
        from the server.

        * Set our state to BREAK to confirm that we have received the 'paused' notification.
        * We own the cmd lock; if breakpoint isn't null, start a *separate* client thread to
          create the breakpoint and do any backtrace required to establish its $PC.

        We will implicitly hand the cmd lock off to the client thread if we create it.

        @param pause_notification the line sent by the server indicating the BP location.
        @return True if the listener thread still owns the cmd lock. False if we handed
            ownership off to the client
        """
        self._process_state = ProcessState.BREAK  # Confirm the BREAK status first.
        own_lock = True

        flagBitNum, flagsAddr = self._parse_break_response(pause_notification)
        if flagsAddr != 0:
            # We have hit a breakpoint. (If flagsAddr == 0, then we interrupted the device.)
            sig = breakpoint.Breakpoint.make_signature(flagBitNum, flagsAddr)
            bp = self._breakpoints.get_bp_for_sig(sig)
            if bp is None:
                # We haven't seen it before. We need to register it, which requires a bit
                # of discussion with the server. Spawn a thread to have that conversation.
                register_thread = breakpoint.BreakpointCreateThread(self, sig)
                register_thread.start()
                own_lock = False  # Ownership of the cmd lock passes to register_thread.
                msg = None  # Let the register_thread give the report.
            else:
                msg = f'Paused at breakpoint, {bp}'
                bp.enabled = True  # Definitionally, it's enabled, whether or not we thought so.
        else:
            msg = "Paused by debugger."

        # Tell the user as much as we know about why we're stopped.
        if msg is not None:
            submitted = False
            while self._alive and not submitted:
                try:
                    self._print_q.put((msg, MsgLevel.INFO), timeout=Debugger.QUEUE_TIMEOUT)
                    submitted = True
                except queue.Full:
                    continue

        return own_lock


    def _conn_listener(self):
        """
        Run as its own thread; listens for data on the serial connection and also
        sends commands out over the connection.

        As new lines are received, they are either routed to the printer queue
        or the debugger recv queue for processing.
        """
        self.verboseprint(f'Starting connection listener thread {threading.get_ident()}')
        own_lock = False
        try:
            while self._alive:
                assert not own_lock  # We shouldn't carry lock ownership around the loop.

                # By default, this thread will attempt to restart the connection if
                # it is suddenly disconnected.
                self._restart_responsibility = ConnRestart.INTERNAL

                if self._process_state == ProcessState.BREAK:
                    # The device is guaranteed to be in the debugger service. Therefore, we wait
                    # for commands to be sent to us from the Debugger to relay to the device.

                    self.__flush_recv_q()
                    try:
                        (msgline, response_type) = self._send_q.get(timeout=Debugger.QUEUE_TIMEOUT)
                    except queue.Empty:
                        continue

                    # Now that we have data from the client to send to the device, the client is
                    # waiting on our response. It's the client's responsibility to handle disconnects here.
                    self._restart_responsibility = ConnRestart.CLIENT
                    self.__send_msg(msgline, response_type)
                    self._restart_responsibility = ConnRestart.INTERNAL
                else:
                    # Process state is either RUNNING or UNKNOWN.

                    # We need to listen for traffic from the device in case it spontaneously
                    # emits a debug_print() or trace() message, or hits a breakpoint and
                    # reports that fact to us. If we do hit a BP, we may need to issue commands
                    # to get more info about the breakpoint -- in which case, we'll need to own
                    # the cmd lock.

                    # The client may also want to start sending commands at any time. In which case
                    # they may already own the cmd lock. If they want to send commands but *don't*
                    # own the cmd lock, then they will have raised _cmd_event. In which case we
                    # should not even contend for the lock.
                    if not self._cmd_event.isSet():
                        # We don't *think* the Repl is waiting for the lock. Try to get it ourselves.
                        # (Access lock directly, don't use get_cmd_lock(), so we don't confuse
                        # ourselves by setting the Event object. That's for client-priority locking
                        # only.)
                        own_lock = self._submit_lock.acquire(blocking=False)

                    if not own_lock:
                        # Send any pending outbound data.
                        if self._send_q.qsize() == 0:
                            # ... client owns the lock, but didn't submit anything yet?
                            # Give them a chance to act.
                            time.sleep(0)

                        if self._send_q.qsize() > 0:
                            # If a command is waiting to be sent, *someone* should own the send lock.
                            assert self._submit_lock.locked()

                            # Client's responsibility to handle disconnects if they have a cmd-response
                            # pattern for us to handle.
                            self._restart_responsibility = ConnRestart.CLIENT

                            # Ensure the recv_q is empty; discard any pending lines, since they're
                            # now all unclaimed.
                            self.__flush_recv_q()

                            # Send the outbound line.
                            (msgline, response_type) = self._send_q.get(block=False)
                            self.__send_msg(msgline, response_type)
                            if self._process_state == ProcessState.BREAK:
                                # We changed process states to BREAK via this msg.
                                # Back to the main loop top, switch into send-biased mode.
                                time.sleep(0)
                                continue

                            # Back to passive monitoring mode; we manage our own reconnects.
                            self._restart_responsibility = ConnRestart.INTERNAL
                    else:
                        # Command submission is blocked because we own the cmd lock.
                        assert own_lock
                        assert self._send_q.qsize() == 0

                        # Ideally we would have a way to interrupt this if the client
                        # wants to fill the _send_q while we're waiting on a silent
                        # channel, but I don't have a clean way to select() on both at
                        # once. Instead we rely on the short timeout we specified when
                        # opening the connection to bring us back to the top of the loop.
                        # We'll release lock ownership on our way back out.
                        line = self._conn.readline().decode("utf-8").strip()
                        submitted = False

                        if len(line) == 0:
                            # Didn't get a line; timed out. Give client opportunity to
                            # acquire lock and send.
                            self.release_cmd_lock()
                            own_lock = False
                            time.sleep(0)  # Yield to other threads; anyone else want the lock?
                            continue
                        elif line.startswith(protocol.DBG_RET_PRINT):
                            # got a message for the user from debug_msg() or trace().
                            # forward it to the ConsolePrinter.
                            while self._alive and not submitted:
                                try:
                                    self._print_q.put((line[1:], MsgLevel.DEVICE),
                                                      timeout=Debugger.QUEUE_TIMEOUT)
                                    submitted = True
                                except queue.Full:
                                    continue
                        elif line.startswith(protocol.DBG_PAUSE_MSG):
                            # Server has informed us that it switched to break mode.
                            # (e.g. program-triggered hardcoded breakpoint.)
                            # We may hand off ownership of the lock to a thread spawned in
                            # __acknowledge_pause().
                            own_lock = self.__acknowledge_pause(line)
                        else:
                            # Got a line of something but it didn't start with '>'.
                            # Either it _is_ for the user and we connected to the socket mid-message,
                            # or we received a legitimate response to a query we sent to the server.
                            # Either way, we forward it to the printer, since we don't expect to
                            # receive a response to a command in this state.
                            while self._alive and not submitted:
                                try:
                                    self._print_q.put((line, MsgLevel.DEVICE),
                                                      timeout=Debugger.QUEUE_TIMEOUT)
                                    submitted = True
                                except queue.Full:
                                    continue

                        # Client now has opportunity to acquire lock and send commands.
                        if own_lock:
                            # May have been released in __acknowledge_pause(); verify
                            # own_lock before release, here.
                            self.release_cmd_lock()
                            own_lock = False
                            time.sleep(0)  # Yield to other threads; anyone else want the lock?

        except OSError as e:
            # Generally means our connection has unexpectedly closed on us.
            # Set flags indicating that the connection has failed.
            # One way or another, this thread is about to terminate.
            self._alive = False
            self._disconnect_err = True

            try:
                self.msg_q(MsgLevel.ERR, "Debugger connection unexpectedly closed")
                self.verboseprint(str(e))
                self._conn.close()
            except Exception:
                pass

            if own_lock:
                # Release this before opening a new connection thread (if we have restart
                # responsibility)..
                self.release_cmd_lock()
                own_lock = False

            if self._restart_responsibility == ConnRestart.INTERNAL:
                # The client is not actively monitoring the connection. We should attempt to restart
                # the connection so we can continue to passively listen for debug_print() and
                # trace() messages. If reconnection is sucessful, this will create a new listener
                # thread that takes the place of this one.
                self.reconnect()

                # At this point, _alive, _conn, etc. are all owned by the new _conn_listener
                # thread. We shouldn't touch *any* internal state, just leave immediately.
            else:
                assert self._restart_responsibility == ConnRestart.CLIENT
                # The client is monitoring the connection. Debugger.__wait_response() will
                # see that _disconnect_err is set to True and throw DisconnectedException to
                # the client, which will then determine whether to restart the connection.
                # We're done.
                pass
        finally:
            self.verboseprint(f'Exiting connection listener thread {threading.get_ident()}')
            if own_lock:
                self.release_cmd_lock()


    def __wait_response(self):
        """
        Wait for a response on recv_q from within send_cmd().
        Raise an exception if the server connection disconnected.
        """
        if not self._alive or self._disconnect_err:
            raise DisconnectedException()

        max_attempts = max(self.get_conf("dbg.poll.retry"), 1)
        attempt_timeout = max(self.get_conf("dbg.poll.timeout"), 10.0) / 1000.0
        for i in range(0, max_attempts):
            if not self._alive or self._disconnect_err:
                raise DisconnectedException()

            try:
                line = self._recv_q.get(timeout=attempt_timeout)
            except queue.Empty:
                # Didn't get a response in time.
                continue

            # print("<-- %s" % line.strip())
            self._recv_q.task_done()
            return line

        # Didn't get a response in enough time. Assume we got disconnected.
        # Shut down the thread cleanly from our side.
        self._alive = False
        self._disconnect_err = True
        self.msg_q(MsgLevel.ERR, "Timeout waiting for response from device.")
        raise DisconnectedException()


    def send_cmd(self, dbg_cmd, result_type):
        """
        Send a low-level debugger command across the wire and return the results.

        @param dbg_cmd either a formatted command string or list of cmd and arguments.
        @param result_type an integer/enum specifying whether to expect 0, 1, or 'n'
        ($-terminated list) lines in response.

        @throws NoServerConnException if not connected to the device.
        @throws DisconnectedException if a disconnect happens during communication.
        @throws InvalidConnStateException if we need to interrupt the sketch to send
                the command and cannot affirmatively do so.
        @throws RuntimeError if result_type is invalid.

        @return type varies based on result_type: SILENT => None; ONELINE => a single
        string response line; LIST => a List of string response lines.
        """

        if not self.is_open():
            raise NoServerConnException("Error: No debug server connection open")

        if self._process_state != ProcessState.BREAK and dbg_cmd != protocol.DBG_OP_BREAK:
            # We need to be in the BREAK state to send any commands to the service
            # besides the break command itself. Send that first..
            if not self.send_break():
                raise InvalidConnStateException("Could not pause device sketch to send command.")

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
                line = self.__wait_response()

            return line
        elif result_type == Debugger.RESULT_LIST:
            lines = []
            while True:
                thisline = self.__wait_response()
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
        """
        Send a 'break' command to the device.

        If we are already at a breakpoint, register it in our breakpoint database if
        this is the first we're learning of that bp.
        """

        break_ok = self.send_cmd(protocol.DBG_OP_BREAK, Debugger.RESULT_ONELINE)
        if break_ok.startswith(protocol.DBG_PAUSE_MSG):
            self._process_state = ProcessState.BREAK
            flagBitNum, flagsAddr = self._parse_break_response(break_ok)
            if flagsAddr != 0:
                # We have hit a breakpoint. (If flagsAddr == 0, then we interrupted the device.)
                sig = breakpoint.Breakpoint.make_signature(flagBitNum, flagsAddr)
                bp = self._breakpoints.get_bp_for_sig(sig)
                if bp is None:
                    # We haven't seen it before. We need to register it, which requires a bit
                    # of discussion with the server.
                    self.discover_current_breakpoint(sig)  # Will print a msg to user, too.
                else:
                    self.msg_q(MsgLevel.INFO, f'Paused at breakpoint, {bp}')
                    bp.enabled = True  # Definitionally, it's enabled, whether or not we thought so.
            else:
                self.msg_q(MsgLevel.INFO, "Paused by debugger.")

            return True
        else:
            self._process_state = ProcessState.UNKNOWN
            self.msg_q(MsgLevel.WARN, "Could not interrupt sketch.")
            return False


    def send_continue(self):
        self.clear_frame_cache()  # Backtrace is invalidated by continued execution.
        continue_ok = self.send_cmd(protocol.DBG_OP_CONTINUE, Debugger.RESULT_ONELINE)
        if continue_ok == "Continuing":
            self._process_state = ProcessState.RUNNING
            self.msg_q(MsgLevel.INFO, "Continuing...")
        else:
            self._process_state = ProcessState.UNKNOWN
            self.msg_q(MsgLevel.WARN, "Could not continue sketch.")
            self.msg_q(MsgLevel.WARN, "Received unexpected response [%s]" % continue_ok)


    def reset_sketch(self):
        self.send_cmd(protocol.DBG_OP_RESET, Debugger.RESULT_SILENT)
        self._process_state = ProcessState.UNKNOWN


    def get_registers(self):
        """
        Get snapshot of system registers.
        """
        if len(self._arch) == 0:
            self.msg_q(MsgLevel.WARN,
                       "Warning: No architecture specified; cannot assign specific registers")
            register_map = ["general_regs"]
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
                if num_general_regs == -1:  # Undefined architecture; take all of them.
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
            self.msg_q(MsgLevel.WARN, f"Warning: cannot set memory poke size = {size}; using 1")
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
            self.msg_q(MsgLevel.WARN, f"Warning: cannot set memory fetch size = {size}; using 1")
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

    def set_bit_flag(self, flags_addr, bit_num, val):
        """
        In a bitfield flags variable, set the bit 'bit_num' to val (0 or 1).
        """
        self.send_cmd([protocol.DBG_OP_SET_FLAG, bit_num, flags_addr, int(val)], Debugger.RESULT_SILENT)

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
            return None  # Debugger server does not have memstats capability compiled in.
        elif len(lines) != len(mem_report_fmt):
            self.msg_q(MsgLevel.WARN,
                       "Warning: got response inconsistent with expected report format for arch.")
            return None  # Debugger server didn't respond with the right mem_list_fmt..?!

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
            if self._frame_cache_complete:
                # We've traced all the backtrace there is, just return it.
                return self._cached_frames
            elif limit is not None and len(self._cached_frames) >= limit:
                # We already have a backtrace cache long enough to accommodate this request
                return self._cached_frames[0:limit]

        # We need to go deeper.

        self.verboseprint(f'Scanning backtrace (limit={limit})')
        ramend = self._arch["RAMEND"]
        ret_addr_size = self._arch["ret_addr_size"]  # nr of bytes on stack for a return address.

        if not self._cached_frames or not len(self._cached_frames):
            # We are starting the backtrace at the top.
            # Start by establishing where we are right now.
            regs = self.get_registers()
            pc = regs["PC"]
            sp = regs["SP"]

            frames = []
            frame = stack.CallFrame(self, pc, sp)
            frames.append(frame)
        else:
            # We have some backtrace already available.
            frames = self._cached_frames
            frame = frames[-1]

            pc = frame.addr
            sp = frame.sp

        # Walk back through the stack to establish the method calls that got us
        # to where we are, up to either the limits of traceability, the top of the stack,
        # or the user-requested limit..
        while sp < ramend and pc != 0 and (limit is None or len(frames) < limit):
            if frame.name is None:
                self._frame_cache_complete = True
                break  # We've hit the limit of traceable methods

            self.verboseprint(f"function {frame.name} has frame {frame.frame_size}; "
                              f"sp: {sp:04x}, pc: {pc:04x}")

            sp += frame.frame_size  # move past the stack frame

            # next 'ret_addr_size' bytes are the return address consumed by RET opcode.
            # pop the bytes off 1-by-1 and consume them as the ret_addr (PC in next fn)
            pc = self.get_return_addr_from_stack(sp + 1)
            sp += ret_addr_size
            self.verboseprint(f"returning to pc {pc:04x}, sp {sp:04x}")

            if sp >= ramend or pc == 0:
                break  # Not at a place valid to record as a frame.

            frame = stack.CallFrame(self, pc, sp)
            frames.append(frame)

        self._cached_frames = frames  # Cache this backtrace for further lookups.

        if sp >= ramend or pc == 0:
            # Stack trace has bottomed out.
            self._frame_cache_complete = True

        # Return the requested subset of the stack trace.
        return frames[0:limit]

    def clear_frame_cache(self):
        """ Clear cached backtrace information. """
        self._cached_frames = None
        self._frame_cache_complete = False

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
            return None  # No such frame.

        pc = frame_regs["PC"]
        return self._debug_info_types.getScopesForPC(pc, include_global=False)


    def get_return_addr_from_stack(self, stack_addr):
        """
        Given a stack_addr pointing to the lowest memory address of a
        return address pushed onto the stack, return the associated return address.
        """
        ret_addr_size = self._arch["ret_addr_size"]  # nr of bytes on stack for a return address.
        ret_addr = 0
        for i in range(0, ret_addr_size):
            # Because AVR is a little-endian machine, it pushes the low-byte of the return
            # address, then the high byte -- but since the stack grows downward, this means
            # the high byte will actually be at the lower memory address (essentially making
            # return addrs on the stack a single 'big endian' exception to the memory order).
            v = self.get_sram(stack_addr + i, 1)
            ret_addr = (ret_addr << 8) | (v & 0xFF)
        ret_addr = ret_addr << 1  # AVR: LSH all PC values read from memory by 1.
        return ret_addr


    def discover_current_breakpoint(self, sig):
        """
        If we're paused at a new breakpoint with signature 'sig', identify its $PC and register it
        in our breakpoint database.

        Invoked within send_cmd() if we issued a redundant break cmd and discovered we're already
        at a breakpoint, OR from a BreakpointCreateThread if we hit a breakpoint while in passive
        listening mode.
        """
        # Get partial backtrace to establish breakpoint location. Top of stack is
        # the dbg_service; breakpoint is in whatever's below that.
        frames = self.get_backtrace(limit=2)
        if len(frames) < 2:
            # Not really at a useful breakpoint? Nothing to register w/o a $PC.
            msg = 'Paused at unknown breakpoint.'
        else:
            frame = frames[1]
            bp = self._breakpoints.register_bp(frame.addr, sig, False)
            msg = f'Paused at breakpoint, {bp}'

        self.msg_q(MsgLevel.INFO, msg)

    def _parse_break_response(self, pause_notification):
        # The pause notification is of the form: 'Paused {flagBitNum:x} {flagsAddr:x}'
        tokens = pause_notification.split()
        if len(tokens) < 3:
            flagBitNum = 0
            flagsAddr = 0
        else:
            try:
                flagBitNum = int(tokens[1], base=16)
                flagsAddr = int(tokens[2], base=16)
            except ValueError:
                # Couldn't parse breakpoint addr. Ignore it.
                flagBitNum = 0
                flagsAddr = 0

        return flagBitNum, flagsAddr


