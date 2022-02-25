# (c) Copyright 2022 Aaron Kimball
"""
Breakpoint tracking, set/disable, and single-step management.

Supports repl commands:
    breakpoint create <addr>  -- creates a new hardware (dynamic) breakpoint.
    breakpoint list         - list known breakpoints
    breakpoint enable #n    - enable breakpoint by id. If at a breakpoint, #n is optional, use
                              current.
    breakpoint disable #n   - disable breakpoint by id. If at a breakpoint, #n is optional, use
                              current.
    breakpoint delete #n    - disable and forget breakpoint by id. (hardware breakpoints only)
    breakpoint sync         - Syncs enable/disable info from debugger up to device.

    `bp` is a synonym for `breakpoint` in repl.

Future work:
    step return             - Run all opcodes thru end of this method/call frame.
"""

import threading

import arduino_dbg.arch as arch
import arduino_dbg.binutils as binutils
import arduino_dbg.debugger as dbg
from arduino_dbg.repl_command import CompoundCommand, CompoundHost
from arduino_dbg.term import MsgLevel


class SoftwareBreakpointError(object):
    """ Raised when an operation cannot be performed on a software breakpoint """
    pass


class BreakpointDatabase(object):
    """
    Database of known breakpoints in the sketch being debugged.

    These may be explicitly set by the client or discovered as
    we encounter breakpoints in the running program that report back
    to the client when encountered.
    """

    def __init__(self, debugger):
        self._debugger = debugger
        self.reset()

    def __repr__(self):
        bp_strs = list(map(repr, self._breakpoints))  # Format breakpoint strs

        # Mark enabled breakpoints with '[*]', disabled with '[ ]'
        bp_enables = map(lambda bp: bp.enabled, self._breakpoints)
        bp_enable_strs = list(map(lambda flag: '[' + (flag * '*') + ((not flag) * ' ') + '] ',
                                  bp_enables))

        nums = list(map(lambda i: f'#{i}. ', range(0, len(bp_strs))))   # Format "#0. ", "#1. ", ...
        lines = list(map(''.join, zip(nums, bp_enable_strs, bp_strs)))  # connect those into 1 str/line.

        lines.insert(0, "id  en  typ  breakpoint")
        lines.insert(1, "-----------------------")
        return '\n'.join(lines)

    def reset(self):
        """
        Hard-clear and reset all breakpoint db state. (Intended for testing.)
        Does not de-register breakpoints with arch_iface, etc. or send I/O to device.
        """
        self._breakpoints = []
        self._pc_to_bp = {}
        self._sig_to_bp = {}


    def register_bp(self, pc, signature, is_dynamic):
        """
        Register a new breakpoint; either created by client (is_dynamic=True) or as we
        encounter it live in the set program (is_dynamic=False).
        """

        if pc in self._pc_to_bp:
            return self._pc_to_bp[pc]  # Already registered.

        if pc is None:
            raise Exception("Cannot declare breakpoint at undefined address")

        bp = Breakpoint(self._debugger, pc, signature, is_dynamic)

        self._breakpoints.append(bp)
        self._pc_to_bp[pc] = bp
        self._sig_to_bp[signature] = bp
        return bp


    def get_bp_for_pc(self, pc):
        """
        Return the breakpoint known at $PC or None if no such known breakpoint.
        """

        if pc in self._pc_to_bp:
            return self._pc_to_bp[pc]
        else:
            return None

    def get_bp_for_sig(self, sig):
        """
        Return the breakpoint with the specified signature or None if no such known breakpoint.
        """
        if sig in self._sig_to_bp:
            return self._sig_to_bp[sig]
        else:
            return None

    def get_bp(self, idx):
        """
        Return the n'th breakpoint or None if overrunning the list length.
        """
        if idx >= len(self._breakpoints):
            return None

        return self._breakpoints[idx]

    def delete(self, idx):
        """
        Drop the breakpoint entry with the specified index.
        """
        if not self._breakpoints[idx].is_dynamic:
            raise SoftwareBreakpointError()  # Cannot delete software bp. Hardware bps only.

        try:
            self._breakpoints[idx].disable()
        except arch.BreakpointNotEnabledError:
            pass  # That's fine; it was already disabled.

        del self._breakpoints[idx]

    def breakpoints(self):
        """
        Get the list of breakpoints.
        """
        return self._breakpoints

    def allow_create_breakpoint(self):
        """
        Return True if this architecture supports creating breakpoints dynamically.
        """
        return (self._debugger.get_arch_conf("dynamic_breakpoints") and
                self._debugger.arch_iface.get_num_hardware_breakpoints() > 0)


class Breakpoint(object):
    """
    Either a hardware breakpoint created by the user, or an individual software breakpoint
    location that has made itself known to the debugger.

    Software breakpoints cannot be created directly, but they can be listed, and
    selectively enabled/disabled with flags. Hardware breakpoints can be installed or
    deleted.
    """

    @staticmethod
    def make_sw_signature(bit_num, flag_bits_addr):
        """
        Make a unique breakpoint signature from its server-provided elements:
        a bit number in a flags word, and the address of that flags word in RAM.
        """
        # Format is just a tuple.
        return ('SW', bit_num, flag_bits_addr)

    @staticmethod
    def make_hw_signature(pc_addr):
        """
        Make a unique breakpoint signature for a hardware bp at a specified $PC.
        """
        return ('HW', pc_addr)


    def __init__(self, debugger, pc, signature, is_dynamic):
        self._debugger = debugger

        self.is_dynamic = is_dynamic
        self.pc = pc                    # Program counter @ breakpoint.
        self.signature = signature      # A unique handle id for the breakpoint.
                                        # For SW breakpoints, we see this as a (bitnumber,
                                        # bitflags_addr) pair, shared w/ server-side.
                                        # HW breakpoints are represented just by a PC addr.

        self.sym = debugger.function_sym_by_pc(pc)
        if self.sym is None:
            debugger.msg_q(MsgLevel.WARN, f'New breakpoint at {pc:04x} not within known method')
            self.name = '???'
            self.demangled = '???'
        else:
            self.name = self.sym.name
            self.demangled = self.sym.demangled
            debugger.verboseprint(f'New breakpoint at {pc:04x} in method {self.demangled}')

        self.inline_chain = debugger.get_debug_info().getMethodsForPC(pc)
        self.demangled_inline_chain = list(map(binutils.demangle, self.inline_chain))

        self.source_line = binutils.pc_to_source_line(debugger.elf_name, pc) or None

        self.enabled = not is_dynamic  # SW breakpoints start enabled.


    def __repr__(self):
        if self.is_dynamic:
            bp_typ = 'hw'
        else:
            bp_typ = 'sw'

        s = f'[{bp_typ}] $PC=0x{self.pc:04x}:  '

        if len(self.demangled_inline_chain) > 1:
            s += ' inlined in '.join(self.demangled_inline_chain)
        else:
            s += f'{self.demangled}'

        if self.source_line:
            s += f'  ({self.source_line})'

        return s

    def enable(self):
        """
        Enable this breakpoint.
        """
        if self.is_dynamic:
            self._debugger.arch_iface.create_hw_breakpoint(self)
            self.enabled = True
        else:
            bit_num, flag_bits_addr = self._read_sig()
            if flag_bits_addr == 0:
                self._debugger.msg_q(MsgLevel.ERR,
                                     'Error: Breakpoint has null bitfield addr, cannot enable')
            else:
                self._debugger.set_bit_flag(flag_bits_addr, bit_num, 1)
                self.enabled = True


    def disable(self):
        """
        Disable this breakpoint.
        """
        if self.is_dynamic:
            try:
                self._debugger.arch_iface.remove_hw_breakpoint(self)
            except arch.BreakpointNotEnabledError:
                self.enabled = False  # It's *definitely* disabled. Still raise.
                raise

            self.enabled = False
        else:
            bit_num, flag_bits_addr = self._read_sig()
            if flag_bits_addr == 0:
                self._debugger.msg_q(MsgLevel.ERR,
                                     'Error: Breakpoint has null bitfield addr, cannot disable')
            else:
                self._debugger.set_bit_flag(flag_bits_addr, bit_num, 0)
                self.enabled = False


    def sync(self):
        """
        Sync the local enable status of this breakpoint up to the debugger.
        """
        if self.is_dynamic:
            raise Exception("Dynamic breakpoints synchronized only through scheduler")
        else:
            bit_num, flag_bits_addr = self._read_sig()
            if flag_bits_addr == 0:
                return  # Cannot sync this breakpoint; nothing to do.

            self._debugger.set_bit_flag(flag_bits_addr, bit_num, int(self.enabled))

    def _read_sig(self):
        """
        Interpret our 'signature' field into identifying info about the breakpoint 'handle'
        we can use to enable/disable it.
        """
        if self.is_dynamic:
            _, pc_addr = self.signature
            return pc_addr
        else:
            _, bit_num, flag_bits_addr = self.signature
            return bit_num, flag_bits_addr




class BreakpointCreateThread(threading.Thread):
    """
    A thread that will establish what $PC a new breakpoint sits at, and register the
    breakpoint with the debugger's breakpoint database.

    This is spawned by the debugger's listener thread, since it cannot run debug commands
    within the thread due to queue usage. It is assumed that the listener thread owned
    the cmd lock already, and when this thread is started, ownership of the lock passes to
    this thread. We are responsible for releasing the lock when we're done.
    """

    def __init__(self, debugger, sig):
        super().__init__(name="Register breakpoint")
        self._debugger = debugger
        self._sig = sig

    def run(self):
        """
        Interact with the debugger to establish the $PC for this breakpoint
        """
        try:
            self._debugger.discover_current_breakpoint(self._sig)
        except dbg.DebuggerIOError as dioe:
            self._debugger.msg_q(MsgLevel.ERR, f'Error while analyzing breakpoint: {dioe}')
        finally:
            # No matter what happens, we must relinquish this lock when done.
            self._debugger.release_cmd_lock()


@CompoundHost
class BreakpointCommands(object):
    """
    Handler for breakpoint repl commands.
    """

    def __init__(self, repl):
        self._repl = repl

    @CompoundCommand(kw1=['breakpoint', 'bp'], kw2=['enable', 'e'], cls='BreakpointCommands')
    def enable(self, args):
        """
        Enable a breakpoint

            Syntax: breakpoint enable <id>

        Enables a breakpoint, specified by its id from `breakpoint list`.
        See also `help breakpoint disable`.
        """
        debugger = self._repl.debugger()

        if len(args) == 0:
            debugger.msg_q(MsgLevel.INFO, "Syntax: breakpoint enable <id>")
            return

        id = int(args[0])
        bp = debugger.breakpoints().get_bp(id)
        if bp is None:
            debugger.msg_q(MsgLevel.ERR, f'Error: No such breakpoint id: {id}')
            return

        try:
            bp.enable()
        except arch.HWBreakpointsFullError:
            debugger.msg_q(MsgLevel.ERR, 'Error: No hardware breakpoint available')
            debugger.msg_q(MsgLevel.ERR, 'You must first disable a different hw breakpoint.')
        except arch.BreakpointAddrExistsError:
            debugger.msg_q(MsgLevel.ERR, 'A breakpoint is already enabled at this address.')
            debugger.msg_q(MsgLevel.ERR, 'You must disable the other breakpoint to enable this one.')


    @CompoundCommand(kw1=['breakpoint', 'bp'], kw2=['disable', 'd'], cls='BreakpointCommands')
    def disable(self, args):
        """
        Disable a breakpoint

            Syntax: breakpoint disable <id>

        Disables a breakpoint, specified by its id from `breakpoint list`. Disabled
        breakpoints do not stop program execution when encountered by the sketch. They can
        be re-enabled later with `breakpoint enable`.

        If the program is currently paused at a breakpoint that you then disable,
        execution will not resume until you explicitly `continue` execution.
        """
        if len(args) == 0:
            self._repl.debugger().msg_q(MsgLevel.INFO, "Syntax: breakpoint disable <id>")
            return

        id = int(args[0])
        bp = self._repl.debugger().breakpoints().get_bp(id)
        if bp is None:
            self._repl.debugger().msg_q(MsgLevel.ERR, f'Error: No such breakpoint id: {id}')
            return

        try:
            bp.disable()
        except arch.BreakpointNotEnabledError:
            pass  # The user got what they wanted. Don't raise an error msg.

    @CompoundCommand(kw1=['breakpoint', 'bp'], kw2=['list'], cls='BreakpointCommands')
    def list_bps(self, args):
        """
        List known breakpoints

            Syntax: breakpoint list

        Breakpoints are catalogued as they are encountered in the running program and
        assigned sequentially increasing id numbers in the debugger. You can toggle these
        breakpoints on and off with the `breakpoint enable` and `breakpoint disable`
        commands.
        """
        self._repl.debugger().msg_q(MsgLevel.INFO, self._repl.debugger().breakpoints())

    @CompoundCommand(kw1=['breakpoint', 'bp'], kw2=['delete', 'rm'], cls='BreakpointCommands')
    def delete(self, args):
        """
        Delete a breakpoint

            Syntax: breakpoint delete <id>

        Disables a hardware breakpoint and removes it from our local breakpoints list.
        """

        if len(args) == 0:
            self._repl.debugger().msg_q(MsgLevel.INFO, "Syntax: breakpoint delete <id>")
            return

        id = int(args[0])
        try:
            breakpoint_db = self._repl.debugger().breakpoints()
            bp = breakpoint_db.get_bp(id)
            if bp is None:
                self._repl.debugger().msg_q(MsgLevel.ERR, f'Error: No such breakpoint id: {id}')
            else:
                breakpoint_db.delete(id)  # Disable and remove from local db.
        except SoftwareBreakpointError:
            self._repl.debugger().msg_q(MsgLevel.ERR,
                                        f'Error: Cannot delete software breakpoint #{id}')
        except IndexError:
            self._repl.debugger().msg_q(MsgLevel.ERR, f'Error: No such breakpoint id: {id}')


    @CompoundCommand(kw1=['breakpoint', 'bp'], kw2=['sync'], cls='BreakpointCommands')
    def sync(self, args):
        """
        Sync breakpoint enable/disable state from debugger to device

            Syntax: breakpoint sync

        Ensures hardware breakpoint registers match user-specified breakpoint definitions.

        Software breakpoint disable flags are cleared after resetting the device; this will
        restore their state to that known by the debugger.
        """
        debugger = self._repl.debugger()
        breakpoint_list = debugger.breakpoints().breakpoints()
        n = len(breakpoint_list)
        if n == 0:
            debugger.msg_q(MsgLevel.INFO, '(No breakpoints to sync)')
            return
        elif n == 1:
            debugger.msg_q(MsgLevel.INFO, 'Synchronizing 1 breakpoint definition...')
        else:
            debugger.msg_q(MsgLevel.INFO, f'Synchronizing state for {n} breakpoints...')

        for bp in breakpoint_list:
            if not bp.is_dynamic:
                bp.sync()  # Software breakpoint bits sync'd from breakpoint itself.

        # Hardware breakpoints are synchronized by the global hardware breakpoint mgr,
        # as the Breakpoint objects don't actually correspond 1:1 to hardware bp registers.
        debugger.arch_iface.sync_hw_breakpoints()


    @CompoundCommand(kw1=['breakpoint', 'bp'], kw2=['create', 'new'], cls='BreakpointCommands')
    def create(self, args):
        """
        Create a new breakpoint

            Syntax: breakpoint create <methodName | pcAddr | '.'>

        Creates a new hardware breakpoint (if supported by the device architecture).
        Breakpoints can be created by any of the following location identifiers:
        * A method name, causing breakpoint on method entry,
        * A specific $PC value ('4a2c' or '0x4a2c'), or
        * The current $PC value, indicated by the '.' dot symbol.

        """
        debugger = self._repl.debugger()
        if not debugger.breakpoints().allow_create_breakpoint():
            debugger.msg_q(MsgLevel.ERR, "Device does not support breakpoint creation")
            return

        if len(args) == 0:
            debugger.msg_q(MsgLevel.INFO,
                           "Syntax: breakpoint create <methodName | pcAddr | '.'>")
            return

        def _maybe_parse_hex(s):
            if s.startswith('0x') or s.startswith('0X'):
                s = s[2:]
            try:
                return int(s, base=16)
            except ValueError:
                return None

        addr_arg = args[0]
        maybe_sym = debugger.lookup_sym(addr_arg)  # Is the arg a method name? Maybe.
        pcAddr = None
        if addr_arg == '.':
            frame = debugger.get_top_user_frame()
            assert frame is not None
            pcAddr = frame.break_registers['PC']
        elif maybe_sym is not None:
            pcAddr = maybe_sym.addr
        elif _maybe_parse_hex(addr_arg):
            pcAddr = _maybe_parse_hex(addr_arg)

        if pcAddr is None:
            debugger.msg_q(MsgLevel.ERR, f"Cannot locate breakpoint address: {addr_arg}")
            return

        sig = Breakpoint.make_hw_signature(pcAddr)
        bp = debugger.breakpoints().register_bp(pcAddr, sig, True)

        # If 'sig' was already in the breakpoint database, we should get an existing breakpoint
        # back. Otherwise we create a new breakpoint.
        if bp.enabled:
            debugger.msg_q(MsgLevel.INFO, f"Breakpoint exists: {bp}")
            return

        try:
            debugger.msg_q(MsgLevel.INFO, f"Created breakpoint: {bp}")
            if not bp.enabled:
                bp.enable()
        except arch.BreakpointAddrExistsError:
            debugger.msg_q(MsgLevel.WARN,
                           'A breakpoint is already enabled at this address.')
            debugger.msg_q(MsgLevel.WARN,
                           'You must disable the other breakpoint to enable this one.')
            debugger.msg_q(MsgLevel.WARN,
                           '(Breakpoint was successfully defined, but it is disabled.)')
        except arch.HWBreakpointsFullError:
            debugger.msg_q(MsgLevel.WARN, 'Error: No hardware breakpoint available')
            debugger.msg_q(MsgLevel.WARN,
                           'A different hw breakpoint must be disabled to enable this one.')
            debugger.msg_q(MsgLevel.WARN,
                           '(Breakpoint was successfully defined, but it is disabled.)')




