# (c) Copyright 2021 Aaron Kimball

from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import CIE

import os
import os.path
import queue
from sortedcontainers import SortedDict, SortedList
import threading
import time
import traceback

import arduino_dbg.arch as arch
import arduino_dbg.binutils as binutils
import arduino_dbg.breakpoint as breakpoint
import arduino_dbg.conf_files as conf_files
import arduino_dbg.protocol as protocol
import arduino_dbg.serialize as serialize
import arduino_dbg.stack as stack
from arduino_dbg.symbol import Symbol
import arduino_dbg.term as term
from arduino_dbg.term import MsgLevel
import arduino_dbg.types as types

# The maximum protocol version id we speak.
HOST_MAX_PROTOCOL_VERSION = 1

_LOCAL_CONF_FILENAME = os.path.expanduser("~/.arduino_dbg.conf")
_DEFAULT_HISTORY_FILENAME = os.path.expanduser("~/.arduino_dbg_history")

_DEFAULT_MAX_CONN_RETRIES = 3
_DEFAULT_MAX_POLL_RETRIES = 20
_DEFAULT_POLL_TIMEOUT = 100  # milliseconds
_DEFAULT_MAX_BACKTRACE_DEPTH = 100

_dbg_conf_keys = [
    "arduino.platform",
    "arduino.arch",
    "dbg.backtrace.limit",
    "dbg.colors",
    "dbg.conf.formatversion",
    "dbg.conn.retries",
    "dbg.historyfile",
    "dbg.internal.stack.frames",  # True: show all backtrace frames. False: hide debugger internals.
    "dbg.poll.retry",    # Attempt to listen how many times in __wait_response() ?
    "dbg.poll.timeout",  # When listening to recv_q in __wait_response(), wait how long?
    "dbg.print_die.offset",
    "dbg.verbose",
]

# Mapping from CPUID signature bytes to ('friendly name', 'config name')
CPUID_mappings = {
    # 0x410CC200: ('Cortex-M0 r0p0', '????'),
    # 0x410CC201: ('Cortex-M0 r0p1', '????'),
    # 0x410CC601: ('Cortex-M0+ r0p1', '????'),      # Cortex-M0+ r0p1 (SAMD21, Feather 0)
    # 0x410FC240: ('Cortex-M4 r0p0', '????'),       # Cortex-M4 r0p0 (unknown)
    0x410fc241: ('Cortex-M4 r0p1', 'samd51x19a'),   # Cortex-M4 r0p1 (SAMD51; Feather M4)
    0x0014951e: ('ATmega328', 'atmega328p'),        # Regular 328 has same config as Uno 328p
    0x000f951e: ('ATmega328P', 'atmega328p'),       # Uno (32kb flash, 2kb ram)
    # 0x0016951e: ('ATmega328PB', 'atmega328pb???'),    # Other Mega328 variant. (64kb flash, 4kb ram)
    0x0087951e: ('ATmega32U4', 'atmega32u4'),      # (Leonardo, Micro)
}


class ProcessState(object):
    """
    When we connect to the device, which state are we in?

    Depending on the process state, the connection listener thread is biased to either
    passively listen for dbgprint() and trace() messages from the device, or expect
    command--response interactions to originate from the local client.
    """

    UNKNOWN = 0     # Don't know if sketch is running or note. Bias to assuming it is running.
    RUNNING = 1     # The sketch is definitely running.
    BREAK = 2       # The sketch is definitely parked at a breakpoint / interrupt in the dbg service.
    ONE_STEP = 3    # We instructed the CPU to perform one step of execution only.


class ConnRestart(object):
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


class AsyncCmdExecThread(threading.Thread):
    """
    A thread that will execute a debugger function that may trigger I/O with the debugged device.

    The connection listener thread cannot invoke functions of the debugger that may themselves call
    `send_cmd()`; send_cmd() uses queues to exchange commands and their results with the connection
    I/O thread. Because of this model, if the listener thread enqueues a command, it cannot in the
    same thread dequeue that command to send it.

    If the state machine within the connection listener thread arrives at a situation where it
    should send a command, it must do so asynchronously, through an instance of this thread.

    This thread assumes that it is started when the caller (thread calling this thread's start()
    method) holds the cmd_lock, and that ownership of the cmd_lock passes to this thread. Once the
    command has been executed, this thread will release() the cmd_lock.
    """

    def __init__(self, debugger, cmd_fn, name="Debugger async cmd executor"):
        """
        Initialize a new command executor thread. The 'cmd_fn' argument must be the method to
        invoke, which presumably itself invokes debugger.send_cmd(). This function will be called
        with no arguments (`cmd_fn()`).
        """
        super().__init__(name=name)
        self._debugger = debugger
        self._cmd_fn = cmd_fn

    def run(self):
        """
        Invoke the async command. It is assumed that the debugger's cmd_lock was already acquired,
        and that ownership of the lock passes to this method/thread. We will release the lock when
        the command has been invoked.
        """
        try:
            fn = self._cmd_fn
            fn()
        except DebuggerIOError as dioe:
            self._debugger.msg_q(MsgLevel.ERR, f'Error while invoking async command: {dioe}')
        finally:
            # No matter what happens, we must relinquish this lock when done.
            self._debugger.release_cmd_lock()



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


class DebuggerIOError(Exception):
    """
    Base class for I/O errors that may occur communicating cmds to the device
    debugger service.
    """
    pass


class UnsupportedDebuggerProtocolException(DebuggerIOError):
    """ We cannot interact with a sketch running a newer version of dbglib. """
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
        self._protocol_version = None  # Protocol version running on attached sketch.
        self._print_q = print_q  # Data from serial conn to print directly to console.
        self._history_change_hook = history_change_hook

        self._recv_q = None       # Main debugger client receives responses from server via this q.
        self._send_q = None       # Client(s) may enqueue comms to the server (commands) via this q.

        # We will need demangling service to load an ELF file. While the demangler threads
        # were started as part of main(), they may have been closed in the interim. Ensure
        # they're running now.
        binutils.start_demangle_threads(self._print_q)

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
        self.arch_iface = None       # adbg.arch.ArchInterface implementation; loaded from config.

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
        conf_map["arduino.platform"] = 'auto'
        conf_map["arduino.arch"] = 'auto'
        conf_map["dbg.backtrace.limit"] = _DEFAULT_MAX_BACKTRACE_DEPTH
        conf_map["dbg.colors"] = True
        conf_map["dbg.conf.formatversion"] = serialize.DBG_CONF_FMT_VERSION
        conf_map["dbg.conn.retries"] = _DEFAULT_MAX_CONN_RETRIES
        conf_map["dbg.historyfile"] = _DEFAULT_HISTORY_FILENAME
        conf_map["dbg.internal.stack.frames"] = False
        conf_map["dbg.poll.retry"] = _DEFAULT_MAX_POLL_RETRIES
        conf_map["dbg.poll.timeout"] = _DEFAULT_POLL_TIMEOUT
        conf_map["dbg.verbose"] = False

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
        new_conf = conf_files.load_conf_module("arduino_dbg.platforms", platform_name, self._print_q)
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
        new_conf = conf_files.load_conf_module("arduino_dbg.arch", arch_name, self._print_q)
        if not new_conf:
            return  # Nothing to load.

        self._arch = new_conf  # Lock in the new k/v store.
        # Instantiate class of arch-specific helper methods
        # (Based on new `arch_interface` setting in self._arch)
        arch.load_arch_interfaces()  # Trigger deferred imports of ArchInterface modules.
        self.arch_iface = arch.ArchInterface.make_arch_interface(self)
        mem_map = self.arch_iface.memory_map()  # Initialize and validate memory map
        self.verboseprint('Initialized memory map:\n', mem_map)

        # Clear cached architecture parameters in DWARFExprMachine
        import arduino_dbg.eval_location as el
        el.DWARFExprMachine.hard_reset_state()
        el.DWARFExprMachine([], {}, self)

        # Clear backtrace cache, reprocess with new ArchInterface.
        self.clear_frame_cache()  # Backtrace is invalidated by continued execution.

        if old_int_size is not None:
            # If the width of 'int' or pointer addr changes by virtue of changing the architecture
            # profile, the ELF file must be reloaded.
            new_int_size = self.get_arch_conf("int_size")
            new_addr_size = self.get_arch_conf("ret_addr_size")
            if new_int_size != old_int_size or new_addr_size != old_addr_size:
                self.msg_q(MsgLevel.WARN,
                           f'Arch changed widths: int={new_int_size}, ptr={new_addr_size}. Reloading ELF...')
                self._try_read_elf()


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
        elif key == "arduino.arch":
            self._load_arch()
        elif key == "dbg.verbose":
            self._config_verbose_print()
        elif key == "dbg.historyfile":
            self._config_history_file()
        elif key == 'dbg.backtrace.limit':
            self.clear_frame_cache()  # Current backtrace result invalidated.

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

    def autodetect_cpu(self, cpuid):
        """
        Given a CPU fingerprint detected at runtime by the device and sent via ARCH_SPEC response,
        set the arduino.arch field appropriately.

        Returns True if it detects a known CPU architecture.
        """
        if cpuid == protocol.INVALID_CPU_ID:
            self.msg_q(MsgLevel.ERR, 'Invalid CPU id; cannot autodetect architecture')
            return False

        try:
            arch_friendly_name, arch_conf_name = CPUID_mappings[cpuid]
            self.msg_q(MsgLevel.INFO,
                       f'CPU with signature 0x{cpuid:08x}: detected {arch_friendly_name} '
                       f'architecture. Reloading config...')
            self.verboseprint(f'Got arch conf name: {arch_conf_name}')
            self.set_conf('arduino.arch', arch_conf_name)  # Reconfigure.
            self.msg_q(MsgLevel.INFO, 'Reloading ELF file with updated architecture definition...')
            self._try_read_elf()
            return True
        except KeyError:
            self.msg_q(MsgLevel.WARN,
                       f'Could not determine architecture settings for CPU with id 0x{cpuid:08x}')

        return False

    def check_arch(self):
        """
        If the Arduino architecture is set to 'auto' (autodetect), try to deanonymize it.
        """
        if self.get_conf('arduino.arch') == 'auto':
            # Sending ARCH_SPEC command will identify CPU.
            self.get_arch_specs()

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
            self.msg_q(MsgLevel.INFO, "Use `file <filename.elf>` to load a program image.")
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
                    if sym_type == "STT_FUNC":
                        addr = self.arch_iface.sym_addr_to_pc(sym.entry['st_value'])
                    else:
                        addr = sym.entry['st_value']
                    dbg_sym = Symbol(sym, addr)
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
                        # TODO: What if there are multiple CIEs? (gcc-arm-eabi-none seems to
                        # generate several CIEs, but they're all identical... but that doesn't
                        # need to be the case.)
                        self._frame_cie = cfi_e
                        continue

                    # We've got an FDE for some method.
                    # Find the method with the relevant $PC
                    frame_sym = self.function_sym_by_pc(cfi_e.header['initial_location'])
                    if frame_sym:
                        frame_sym.setFrameInfo(cfi_e)
                        # self.verboseprint("Binding CFI: ", frame_sym, "\n--to--\n", cfi_e.header)
                        # self.verboseprint(f"Bound CFI to method {frame_sym.name}.")
                    else:
                        # We have a CFI that claims to start at this $PC, but no method
                        # claims this address.
                        missing_pc = cfi_e.header['initial_location']
                        if missing_pc is not None and missing_pc != 0:
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
        is_break_cmd = msgline == protocol.DBG_OP_BREAK + '\n'

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
                elif not is_break_cmd and line.startswith(protocol.DBG_PAUSE_MSG):
                    # We got an extra 'Paused' confirmation after a BREAK followed by another cmd.
                    # Just silently ignore; if we're sending commands, we know we're in the BREAK
                    # ProcessState.
                    assert self._process_state == ProcessState.BREAK
                    line = None  # Drop the line and wait for the real response.
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
                elif not is_break_cmd and line.startswith(protocol.DBG_PAUSE_MSG):
                    # We got an extra 'Paused' confirmation after a BREAK followed by another cmd.
                    # Just silently ignore; if we're sending commands, we know we're in the BREAK
                    # ProcessState.
                    assert self._process_state == ProcessState.BREAK
                    line = None  # Drop the line and wait for the real response.
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
                    if line == protocol.DBG_END_LIST:
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

                    if line == protocol.DBG_END_LIST:
                        # That line signaled end of the list.
                        break

            self._recv_q.join()  # Wait for response lines to be acknowledged by debugger.
        elif response_type == Debugger.RESULT_SILENT:
            # Nothing further to process in this thread; no response.
            pass
        else:
            self.msg_q(MsgLevel.ERR, f'Error: unknown response_type {response_type}')

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


    def _discover_bp_and_get_arch_specs_fn(self, sig):
        """
        Returns a combo-method to pass to an AsyncCmdExecThread that invokes both
        discover_current_breakpoint() and get_arch_specs() under the same cmd_lock without requiring
        any arguments. Dispatched in certain circumstances by the conn_listener thread within
        __acknowledge_pause().
        """
        def callable_fn():
            self.get_arch_specs()
            self.discover_current_breakpoint(sig)

        return callable_fn

    def _discover_bp_fn(self, sig):
        """
        Returns a method to pass to an AsyncCmdExecThread that invokes discover_current_breakpoint()
        without requiring any arguments. Dispatched in certain circumstances by the conn_listener
        thread within __acknowledge_pause().
        """
        def callable_fn():
            self.discover_current_breakpoint(sig)

        return callable_fn


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
        prior_state = self._process_state
        self._process_state = ProcessState.BREAK  # Confirm the BREAK status first.
        own_lock = True

        flagBitNum, flagsAddr, hwAddr = self._parse_break_response(pause_notification)
        if prior_state == ProcessState.ONE_STEP:
            # The CPU just ran a single step and has returned to the debug service.
            # Print the hwAddr we arrived at.
            msg = f'$PC=0x{hwAddr:04x}'
        elif flagsAddr != 0:
            # We have hit a breakpoint. (If flagsAddr == 0, then we interrupted the device.)
            sig = breakpoint.Breakpoint.make_sw_signature(flagBitNum, flagsAddr)
            bp = self._breakpoints.get_bp_for_sig(sig)
            if bp is None:
                # We haven't seen it before. We need to register it, which requires a bit
                # of discussion with the server. Spawn a thread to have that conversation.
                if self.get_conf('arduino.arch') == 'auto':
                    # We *also* need to have the async thread get the arch_specs so we
                    # can identify the CPU. Queue up a callable that does both.
                    register_thread = AsyncCmdExecThread(self,
                                                         self._discover_bp_and_get_arch_specs_fn(sig),
                                                         name="Arch detection & register breakpoint")
                else:
                    # Start a thread that identifies the software breakpoint we hit.
                    register_thread = AsyncCmdExecThread(self, self._discover_bp_fn(sig),
                                                         name="Register breakpoint")

                register_thread.start()
                own_lock = False  # Ownership of the cmd lock passes to register_thread.
                msg = None  # Let the register_thread give the report.
            else:
                msg = f'Paused at breakpoint, {bp}'
                bp.enabled = True  # Definitionally, it's enabled, whether or not we thought so.
        elif hwAddr != 0:
            msg = f'Paused at breakpoint; $PC=0x{hwAddr:04x}'
            # TODO(aaron): If we restarted the debugger w/o any knowledge of installed BP's
            # and stumbled on one here, we should register hwAddr. (but how do we know which FPB/DWT
            # register it's in? Need to read them back...) But under most circumstances if we
            # get here the device was actually maybe in a 'ONE_STEP' state but locally we
            # lost that train of thought and were in UNKNOWN state. i.e., this isn't a real
            # permanent breakpoint...
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

        if own_lock and self.get_conf('arduino.arch') == 'auto':
            # We don't know what CPU we're working with and the user has asked us to autodetect it.
            # Since we triggered a breakpoint or otherwise established by passively listening that
            # the CPU is in the 'BREAK' state, this is the earliest opportunity to do that
            # detection; do so before the user wants to run a command.
            cpu_detection_thread = AsyncCmdExecThread(self, self.get_arch_specs,
                                                      name="CPU arch detection")
            cpu_detection_thread.start()
            own_lock = False  # lock ownership passes to executor thread.

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
                    # Process state is either RUNNING, ONE_STEP, or UNKNOWN.

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

        if self._process_state == ProcessState.ONE_STEP and dbg_cmd == protocol.DBG_OP_STEP:
            # In the ONE_STEP state, we expect to be sending a STEP command.
            # Do not trigger the pre-command break below.
            if self._protocol_version is None:
                # One exception to that: if we don't know the protocol version spoken by the
                # sketch, we do need to process a break first.
                if not self.send_break():
                    raise InvalidConnStateException("Could not pause device sketch to send command.")
                # We are, however, going to send a 'step' command next. So remain in the
                # one-step state. (send_break() will have reset it to the BREAK state.)
                self._process_state = ProcessState.ONE_STEP
        elif self._process_state != ProcessState.BREAK and dbg_cmd != protocol.DBG_OP_BREAK:
            # We need to be in the BREAK state to send any commands to the service
            # besides the break command itself. Send that first..
            if not self.send_break():
                raise InvalidConnStateException("Could not pause device sketch to send command.")

        if dbg_cmd != protocol.DBG_OP_BREAK and self._protocol_version > HOST_MAX_PROTOCOL_VERSION:
            # We are not forwards-compatible and unexpected results may occur if we attempt to
            # debug a device running a newer version of the protocol than we speak. Stop here.
            raise UnsupportedDebuggerProtocolException(
                f'Cannot send command to device running debugger protocol v{self._protocol_version}')

        if self.get_conf("arduino.arch") == 'auto' and dbg_cmd != protocol.DBG_OP_ARCH_SPEC and \
                dbg_cmd != protocol.DBG_OP_BREAK:
            # We do not know the CPU type yet; the user has asked us to auto-detect it. Do
            # so here. Response is parsed inline in case the 1st command being sent to the device
            # *is* an ARCH_SPEC command, rather than parsing the return value here.
            self.verboseprint('Fetching ARCH_SPEC list to identify \'auto\' architecture.')
            self.get_arch_specs()

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
                elif thisline == protocol.DBG_END_LIST:
                    break
                else:
                    lines.append(thisline.strip())

            if self.get_conf("arduino.arch") == 'auto' and \
                    dbg_cmd.startswith(protocol.DBG_OP_ARCH_SPEC):
                # We just got a set of arch specs back from the device. If we need to change
                # our behavior for the architecture, now's the time, before .
                self.verboseprint("Processing ARCH_SPEC response in debugger...")
                if len(lines) == 0:
                    # On-device debug service is not compliant with our protocol...
                    self.msg_q(MsgLevel.WARN, 'No CPUID included in arch specs')
                    cpu_id = protocol.INVALID_CPU_ID
                else:
                    cpu_id = int(lines[0], base=16)
                    self.verboseprint(f'Got CPU id {cpu_id:08x}')
                self.autodetect_cpu(cpu_id)

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
            prior_state = self._process_state
            self._process_state = ProcessState.BREAK
            flagBitNum, flagsAddr, hwAddr = self._parse_break_response(break_ok)
            if prior_state == ProcessState.ONE_STEP:
                # The CPU just ran a single step and has returned to the debug service.
                # Print the hwAddr we arrived at.
                self.msg_q(MsgLevel.INFO, f'$PC=0x{hwAddr:04x}')
            elif flagsAddr != 0:
                # We have hit a breakpoint. (If flagsAddr == 0, then we interrupted the device.)
                sig = breakpoint.Breakpoint.make_sw_signature(flagBitNum, flagsAddr)
                bp = self._breakpoints.get_bp_for_sig(sig)
                if bp is None:
                    # We haven't seen it before. We need to register it, which requires a bit
                    # of discussion with the server.
                    self.discover_current_breakpoint(sig)  # Will print a msg to user, too.
                else:
                    self.msg_q(MsgLevel.INFO, f'Paused at breakpoint, {bp}')
                    bp.enabled = True  # Definitionally, it's enabled, whether or not we thought so.
            elif hwAddr != 0:
                self.msg_q(MsgLevel.INFO, f'Paused at breakpoint; $PC=0x{hwAddr:04x}')
                # TODO(aaron): May need to register hw bp at hwAddr? See comment in
                # __acknowledge_pause().
            else:
                self.msg_q(MsgLevel.INFO, "Paused by debugger.")

            if self.get_conf("arduino.arch") == 'auto':
                # Now that we've paused the device, autodetect the architecture.
                # send_cmd() will process the result internally and change the arch if needed.
                self.get_arch_specs()

            return True
        else:
            self._process_state = ProcessState.UNKNOWN
            self.msg_q(MsgLevel.WARN, "Could not interrupt sketch.")
            return False


    def send_continue(self):
        """ Continue execution unhindered. """
        self.clear_frame_cache()  # Backtrace is invalidated by continued execution.
        continue_ok = self.send_cmd(protocol.DBG_OP_CONTINUE, Debugger.RESULT_ONELINE)
        if continue_ok == "Continuing":
            self._process_state = ProcessState.RUNNING
            self.msg_q(MsgLevel.INFO, "Continuing...")
        else:
            self._process_state = ProcessState.UNKNOWN
            self.msg_q(MsgLevel.WARN, "Could not continue sketch.")
            self.msg_q(MsgLevel.WARN, "Received unexpected response [%s]" % continue_ok)

    def send_step(self):
        """ Continue execution for a single step. """
        self.check_arch()
        if not self.get_arch_conf('single_step_supported'):
            raise RuntimeError("Single-step mode not supported on this architecture.")

        self.clear_frame_cache()  # Backtrace is invalidated
        self.msg_q(MsgLevel.INFO, "Stepping...")
        self._process_state = ProcessState.ONE_STEP
        self.send_cmd(protocol.DBG_OP_STEP, Debugger.RESULT_SILENT)
        # TODO(aaron): Should this return an acknowledgement?


    def reset_sketch(self):
        self.send_cmd(protocol.DBG_OP_RESET, Debugger.RESULT_SILENT)
        self._process_state = ProcessState.UNKNOWN

    def get_registers(self):
        """
        Get snapshot of system registers.
        """
        self.check_arch()

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

        addr is a physical address.
        """
        if size is None or size < 1:
            self.msg_q(MsgLevel.WARN, f"Warning: cannot set memory poke size = {size}; using 1")
            size = 1

        self.send_cmd([protocol.DBG_OP_POKE, size, addr, value], Debugger.RESULT_SILENT)

    def get_sram(self, addr, size=1):
        """
        Return data from SRAM on the instance.

        This function expects a physical address within the SRAM segment.
        """

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

        This function expects a physical address within the Flash segment.
        """

        result = self.send_cmd([protocol.DBG_OP_FLASHADDR, size, addr], Debugger.RESULT_ONELINE)
        return int(result, base=16)

    def set_bit_flag(self, flags_addr, bit_num, val):
        """
        In a bitfield flags variable, set the bit 'bit_num' to val (0 or 1).
        """
        self.send_cmd([protocol.DBG_OP_SET_FLAG, bit_num, flags_addr, int(val)], Debugger.RESULT_SILENT)

    def get_stack_snapshot(self, count=16, skip=-1):
        """
        Retrieve the `count` words above SP+k (but not past RAMEND),
        where `k` is the number of bytes to skip.

        If `skip` >= 0, k = skip.
        If `skip` == -1, then "auto-skip" the debugger-specific frames.

        @return ($SP, $TOP, snapshot_array). snapshot_array[0] holds the word at $SP for
        a full-descending stack, $SP + 1 for an empty-descending stack;
        subsequent entries hold mem at addresses through $SP + count*word_len. i.e., the "top of the
        stack" is in array[0] and the bottom of the stack (highest physical addr) at array[n].
        The top-of-stack addr '$TOP' is given by $SP + k (full descending) or $SP + k + 1 (empty
        desc) stack.
        """
        self.check_arch()

        if skip < 0:
            # calculate autoskip amount
            skip = stack.get_stack_autoskip_count(self)

        push_word_len = self.get_arch_conf('push_word_len')
        stack_model = self.get_arch_conf('stack_model')
        stack_full = stack_model == 'full_desc' or stack_model == 'full_asc'
        # TODO(aaron): Handle ascending stack architectures. This method only handles descending.

        if stack_full:
            sp_off = 0
        else:
            sp_off = 1

        regs = self.get_registers()
        sp = regs["SP"]
        ramend = self._arch["RAMEND"]
        max_len = (ramend - sp + skip + sp_off) / push_word_len
        count = min(count, max_len)
        self.verboseprint(f'$SP=0x{sp:08x}, RAMEND=0x{ramend:08x}, cnt={count}, word_sz={push_word_len}')
        start_addr = sp + skip + sp_off
        last_addr = min(start_addr + count * push_word_len, ramend)
        self.verboseprint(f'Iterating range {start_addr:08x} ... {last_addr:08x}')
        snapshot = []
        for i in range(start_addr, last_addr, push_word_len):
            v = int(self.send_cmd([protocol.DBG_OP_RAMADDR, push_word_len, i], Debugger.RESULT_ONELINE),
                    base=16)
            # self.verboseprint(f"reading {i:08x} -> {v:08x}")
            snapshot.append(v)
        return (sp, start_addr, snapshot)


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

    def get_arch_specs(self):
        """
        Get CPU settings and capability data (architecture-specific response).
        Typically parsed by the ArchInterface.

        If arduino.arch is 'auto', this will also identify the CPUID and reset arduino.arch within
        the send_cmd() body.
        """
        return self.send_cmd(protocol.DBG_OP_ARCH_SPEC, Debugger.RESULT_LIST)

    ######### Highest-level debugging functions built on top of low-level capabilities

    def __is_internal_stack_frame(self, stack_frame):
        """
        Return True if stack_frame is an 'internal' frame according to
        dbg.internal.stack.frames and thus gets hidden from users by default.
        """
        return stack.is_internal_method_name(stack_frame.name, stack_frame.demangled)

    def __get_internal_method_cnt(self, frame_list):
        """
        Return the number of items on this stack frame list that qualify as internal methods.
        """
        cnt = 0
        for frame in frame_list:
            if self.__is_internal_stack_frame(frame):
                cnt += 1
            else:
                break  # We found the first non-internal method. Internals are never below this.

        return cnt

    def __get_user_backtrace_list(self, show_all_frames, frame_list, limit):
        """
        If show_all_frames is false, return the first 'limit' elements of frame_list that are *not*
        internal stack frames.  If show_all_frames is true, return the first 'limit' elements.

        This is a helper method to be used only within get_backtrace().
        """
        if show_all_frames:
            return frame_list[0:limit]

        start = self.__get_internal_method_cnt(frame_list)

        if limit is None:
            return frame_list[start:]
        else:
            return frame_list[start:limit + start]


    def get_backtrace(self, limit=None, force_unhide=False):
        """
        Retrieve a list of memory addresses representing the top `limit` function calls
        on the call stack. (If limit=None, list all.)

        This method checks the conf prop dbg.internal.stack.frames; if False, this hides
        frames belonging to debugger-internal service methods (like __dbg_service()). Methods
        that call this thus refer to frame ids in a list where such service methods are discarded.

        If force_unhide is True, this overrides dbg.internal.stack.frames

        Return a list of dicts that describe each frame of the stack.
        """
        self.check_arch()

        all_frames = force_unhide or self.get_conf('dbg.internal.stack.frames')
        max_backtrace_limit = self.get_conf('dbg.backtrace.limit')
        if limit is not None and max_backtrace_limit is not None:
            limit = min(limit, max_backtrace_limit)
        elif max_backtrace_limit is not None:
            limit = max_backtrace_limit

        if self._cached_frames:
            internal_cnt = self.__get_internal_method_cnt(self._cached_frames)
            if self._frame_cache_complete:
                # We've traced all the backtrace there is, just return it.
                return self.__get_user_backtrace_list(all_frames, self._cached_frames, limit)
            elif limit is not None and len(self._cached_frames) >= limit and all_frames:
                # We already have a backtrace cache long enough to accommodate this request
                return self._cached_frames[0:limit]
            elif limit is not None and len(self._cached_frames) >= limit + internal_cnt:
                # We already have a backtrace cache long enough to accommodate this request
                return self._cached_frames[internal_cnt:limit + internal_cnt]

        # We need to go deeper.

        self.verboseprint(f'Scanning backtrace (limit={limit})')
        ramend = self._arch["RAMEND"]

        # Parameters for non-link-register-abi return addr calculations:
        ret_addr_size = self.get_arch_conf("ret_addr_size")  # nr of bytes on stack for a return address.
        stack_model = self.get_arch_conf("stack_model")
        if stack_model == 'empty_desc':
            stack_ret_addr_offset = 1
        elif stack_model == 'full_desc':
            stack_ret_addr_offset = 0
        else:
            raise Exception(
                'Do not know how to calculate stack_frame offsets for stack model: '
                f'{stack_model}')

        num_skip = 0  # Number of method frames to skip because they're internal

        if not self._cached_frames or not len(self._cached_frames):
            # We are starting the backtrace at the top.
            # Start by establishing where we are right now.
            regs = self.get_registers()
            self.arch_iface.begin_backtrace(regs)  # Do architecture-specific backtrace setup.

            pc = regs["PC"]
            sp = regs["SP"]

            frames = []
            frame = stack.CallFrame(self, pc, sp, regs)
            frames.append(frame)
            if not all_frames and self.__is_internal_stack_frame(frame):
                num_skip += 1
        else:
            # We have some backtrace already available.
            assert len(self._cached_frames) > 0
            frames = self._cached_frames
            frame = frames[-1]

            # We can pass None to frame.unwind_registers() b/c its output should be cached.
            regs = None
            assert frame.unwound_registers is not None  # Should be cached.
            pc = frame.addr
            sp = frame.sp

            if not all_frames:
                # For purposes of counting toward 'limit', disregard any frames we already
                # have that are internal methods.
                num_skip += self.__get_internal_method_cnt(self._cached_frames)

        # Walk back through the stack to establish the method calls that got us
        # to where we are, up to either the limits of traceability, the top of the stack,
        # or the user-requested limit..
        while sp < ramend and pc != 0 and (limit is None or len(frames) < (num_skip + limit)):
            regs = frame.unwind_registers(regs)
            if frame.name is None:
                self._frame_cache_complete = True
                break  # We've hit the limit of traceable methods

            self.verboseprint(f"function {frame.name} has frame {frame.frame_size}; "
                              f"sp: {sp:04x}, pc: {pc:04x}")

            if regs is None:
                # We didn't have a CFI record, so we fell back to prologue analysis to identify
                # the frame size.

                sp += frame.frame_size  # move past the stack frame

                # top 'ret_addr_size' bytes are the return address consumed by RET opcode.
                # read the last ret_addr_size popped bytes 1-by-1 and consume them as
                # the ret_addr (PC in next fn)
                pc = self.get_return_addr_from_stack(sp + stack_ret_addr_offset - ret_addr_size)
            else:
                # We used the CFI record to unwind the registers.
                sp = regs['SP']  # move past the stack frame
                pc = regs['PC']  # read the unwound $PC / return addr from the frame.

            self.verboseprint(f"returning to pc {pc:04x}, sp {sp:04x}")

            if sp >= ramend or pc == 0:
                break  # Not at a place valid to record as a frame.

            frame = stack.CallFrame(self, pc, sp, regs)
            frames.append(frame)

            if not all_frames and self.__is_internal_stack_frame(frame):
                # We added a valid stack frame, but it's for an internal method, so it doesn't
                # count toward limit.
                num_skip += 1

        self._cached_frames = frames  # Cache this backtrace for further lookups.

        if sp >= ramend or pc == 0:
            # Stack trace has bottomed out.
            self._frame_cache_complete = True

        if len(frames) == max_backtrace_limit:
            # We hit the configured hard limit. (infinite loop of $LR pointing at current method?)
            # Likely suggests we did not parse the CFI records in the ELF file correctly.
            # (Wrong architecture definition?)
            self.msg_q(MsgLevel.WARN,
                       f'Backtrace terminated: Max backtrace limit ({max_backtrace_limit} '
                       f'frames) reached.')
            self.msg_q(MsgLevel.INFO,
                       f'You can change this limit with `set dbg.backtrace.limit = <n>`.\n')

        # Return the requested subset of the stack trace.
        return self.__get_user_backtrace_list(all_frames, self._cached_frames, limit)

    def clear_frame_cache(self):
        """ Clear cached backtrace information. """
        self._cached_frames = None
        self._frame_cache_complete = False

    def get_top_user_frame(self):
        """
        Return the top-most frame on the stack that belongs to the main sketch (as opposed
        to being part of the debugger library).
        """
        i = 0
        last_len = -1
        while True:
            frames = self.get_backtrace(limit=i+1)
            if len(frames) == last_len:
                # There are no further frames to explore (*only* debugger methods on stack?!)
                return None

            if self.__is_internal_stack_frame(frames[-1]):
                i += 1  # Need to explore deeper.
                continue

            return frames[-1]  # We found the first non-internal stack frame.

    def get_frame_regs(self, frame_num, force_unhide=False):
        """
        Return register snapshot as of the specified frame.
        """

        frames = self.get_backtrace(limit=frame_num+1, force_unhide=force_unhide)
        if len(frames) <= frame_num:
            # Cannot find a frame that deep in the backtrace.
            return None
        else:
            return frames[frame_num].break_registers

    def get_frame_vars(self, frame_num, force_unhide=False):
        """
        Return information about variables in scope at the $PC within a stack frame.

        Returns a list of types.MethodType and types.LexicalScope objects that enclose
        the $PC at the requested stack frame, or None if there is no such frame.
        """
        frame_regs = self.get_frame_regs(frame_num, force_unhide)
        if frame_regs is None:
            return None  # No such frame.

        pc = frame_regs["PC"]
        return self._debug_info_types.getScopesForPC(pc, include_global=False)


    def get_return_addr_from_stack(self, stack_addr):
        """
        Given a stack_addr pointing to the lowest memory address of a
        return address pushed onto the stack, return the associated return address.
        """
        self.check_arch()
        # Note: This is possible for AVR, but ARM puts the ret addr in $LR so
        # we'd be reading garbage.
        if self.get_arch_conf("abi_uses_link_register"):
            instruction_set = self.get_arch_conf("instruction_set")
            raise Exception(f"Cannot read return addr from stack on {instruction_set} cpu")

        ret_addr_size = self.get_arch_conf("ret_addr_size")  # nr of bytes on stack for a return address.
        ret_addr = self.get_sram(stack_addr, ret_addr_size)
        return self.arch_iface.mem_to_pc(ret_addr)


    def discover_current_breakpoint(self, sig):
        """
        If we're paused at a new breakpoint with signature 'sig', identify its $PC and register it
        in our breakpoint database.

        Invoked within send_cmd() if we issued a redundant break cmd and discovered we're already
        at a breakpoint, OR from a BreakpointCreateThread if we hit a breakpoint while in passive
        listening mode.
        """
        # Get partial backtrace to establish breakpoint location. Top of stack is
        # the debugger service; breakpoint is in whatever's below that.
        frame = self.get_top_user_frame()
        if frame is None:
            # Not really at a useful breakpoint? Nothing to register w/o a $PC.
            msg = 'Paused at unknown breakpoint.'
        else:
            bp = self._breakpoints.register_bp(frame.addr, sig, False)
            msg = f'Paused at breakpoint, {bp}'

        self.msg_q(MsgLevel.INFO, msg)

    def _parse_break_response(self, pause_notification):
        """
        Parse a "Paused" sentence returned by the device, which indicates why and where the sketch
        has paused for debug mode.

        The pause notification has the following format:
            'Paused {ver:x} {flagBitNum:x} {flagsAddr:x} {hwAddr:x}'
        """
        tokens = pause_notification.split()
        if len(tokens) < 5:
            protoVer = 0
            flagBitNum = 0
            flagsAddr = 0
            hwAddr = 0
        else:
            try:
                protoVer = int(tokens[1], base=16)
                flagBitNum = int(tokens[2], base=16)
                flagsAddr = int(tokens[3], base=16)
                hwAddr = int(tokens[4], base=16)
            except ValueError:
                # Couldn't parse breakpoint addr. Ignore it.
                protoVer = None
                flagBitNum = 0
                flagsAddr = 0
                hwAddr = 0

        if self._protocol_version is None:
            self._protocol_version = protoVer
            if protoVer > HOST_MAX_PROTOCOL_VERSION:
                self.msg_q(
                    MsgLevel.ERR,
                    f'Attached to sketch compiled with debugger protocol {protoVer}; '
                    f'debugger max_ver is {HOST_MAX_PROTOCOL_VERSION}. Unexpected behavior may occur.')
                self.msg_q(
                    MsgLevel.ERR, 'You may need to upgrade this debugger to interact with this sketch.')

        return flagBitNum, flagsAddr, hwAddr


