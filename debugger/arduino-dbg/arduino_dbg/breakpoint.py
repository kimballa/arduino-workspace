# (c) Copyright 2022 Aaron Kimball
"""
Breakpoint tracking, set/disable, and single-step management.

Supports repl commands:
    breakpoint list         - list known breakpoints
    breakpoint enable #n    - enable breakpoint by id. If at a breakpoint, #n is optional, use
                              current.
    breakpoint disable #n   - disable breakpoint by id. If at a breakpoint, #n is optional, use
                              current.
    breakpoint forget #n    - forget the n'th breakpoint in the database.
    breakpoint sync         - Syncs enable/disable info from debugger up to device.

    `bp` is a synonym for `breakpoint` in repl.

Future work:
    breakpoint create $PC   - create a new breakpoint at $PC.
                              (Can we do it by `source.cpp:line` too?)
    step                    - Run one opcode (line?)
    step return             - Run all opcodes thru end of this method/call frame.
"""

import threading

import arduino_dbg.binutils as binutils
import arduino_dbg.debugger as dbg
from arduino_dbg.repl_commands import CompoundCommand, CompoundHost
from arduino_dbg.term import MsgLevel


class BreakpointDatabase(object):
    """
    Database of known breakpoints in the sketch being debugged.

    These may be explicitly set by the client or discovered as
    we encounter breakpoints in the running program that report back
    to the client when encountered.
    """


    def __init__(self, debugger):
        self._debugger = debugger
        self._breakpoints = []
        self._pc_to_bp = {}
        self._sig_to_bp = {}

    def __repr__(self):
        bp_strs = list(map(repr, self._breakpoints))  # Format breakpoint strs

        # Mark enabled breakpoints with '[*]', disabled with '[ ]'
        bp_enables = map(lambda bp: bp.enabled, self._breakpoints)
        bp_enable_strs = list(map(lambda flag: '[' + (flag * '*') + ((not flag) * ' ') + '] ',
                                  bp_enables))

        nums = list(map(lambda i: f'#{i}. ', range(0, len(bp_strs))))   # Format "#0. ", "#1. ", ...
        lines = list(map(''.join, zip(nums, bp_enable_strs, bp_strs)))  # connect those into 1 str/line.

        lines.insert(0, "id  en  breakpoint")
        lines.insert(1, "------------------")
        return '\n'.join(lines)


    def register_bp(self, pc, signature, is_dynamic):
        """
        Register a new breakpoint; either created by client or as we
        encounter it live in the set program.
        """

        if pc in self._pc_to_bp:
            return self._pc_to_bp[pc]  # Already registered.

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

    def forget(self, idx):
        """
        Drop the breakpoint entry with the specified index.
        """
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
        return self._debugger.get_arch_conf("dynamic_breakpoints")


class Breakpoint(object):
    """
    An individual breakpoint location
    """

    @staticmethod
    def make_signature(bit_num, flag_bits_addr):
        """
        Make a unique breakpoint signature from its server-provided elements:
        a bit number in a flags word, and the address of that flags word in RAM.
        """
        # Format is just a tuple.
        return (bit_num, flag_bits_addr)


    def __init__(self, debugger, pc, signature, is_dynamic=False):
        self.pc = pc                    # Program counter @ breakpoint.
        self.is_dynamic = is_dynamic    # True if we created from client; False if static in prgm.

        self.signature = signature      # A unique server-side id for the breakpoint.
                                        # We see this as a (bitnumber, bitflags_addr) pair.

        self._debugger = debugger

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

        self.enabled = True


    def __repr__(self):
        s = f'$PC=0x{self.pc:04x}:  '

        if len(self.demangled_inline_chain) > 1:
            s += ' inlined in '.join(self.demangled_inline_chain)
        else:
            s += '{self.demangled}'

        if self.source_line:
            s += f'  ({self.source_line})'

        return s

    def enable(self):
        """
        Enable this breakpoint.
        """
        bit_num, flag_bits_addr = self.signature
        if flag_bits_addr == 0:
            self._debugger.msg_q(MsgLevel.ERR,
                                 'Error: Breakpoint has null bitfield addr, cannot enable')

        self.enabled = True
        self._debugger.set_bit_flag(flag_bits_addr, bit_num, 1)

    def disable(self):
        """
        Disable this breakpoint.
        """
        bit_num, flag_bits_addr = self.signature
        if flag_bits_addr == 0:
            self._debugger.msg_q(MsgLevel.ERR,
                                 'Error: Breakpoint has null bitfield addr, cannot disable')

        self.enabled = False
        self._debugger.set_bit_flag(flag_bits_addr, bit_num, 0)

    def sync(self):
        """
        Sync the local enable status of this breakpoint up to the debugger.
        """
        bit_num, flag_bits_addr = self.signature
        if flag_bits_addr == 0:
            return  # Cannot sync this breakpoint

        self._debugger.set_bit_flag(flag_bits_addr, bit_num, int(self.enabled))


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
        if len(args) == 0:
            self._repl.debugger().msg_q(MsgLevel.INFO, "Syntax: breakpoint enable <id>")
            return

        id = int(args[0])
        bp = self._repl.debugger().breakpoints().get_bp(id)
        if bp is None:
            self._repl.debugger().msg_q(MsgLevel.ERR, f'Error: No such breakpoint id: {id}')
            return

        bp.enable()


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

        bp.disable()

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

    @CompoundCommand(kw1=['breakpoint', 'bp'], kw2=['forget'], cls='BreakpointCommands')
    def forget(self, args):
        """
        Forget a breakpoint

            Syntax: breakpoint forget <id>

        Drops a breakpoint from the local breakpoints list. This does not change whether or
        not the breakpoint is enabled or disabled on the device.
        """
        if len(args) == 0:
            self._repl.debugger().msg_q(MsgLevel.INFO, "Syntax: breakpoint disable <id>")
            return

        id = int(args[0])
        try:
            self._repl.debugger().breakpoints().forget(id)
        except IndexError:
            self._repl.debugger().msg_q(MsgLevel.ERR, f'Error: No such breakpoint id: {id}')


    @CompoundCommand(kw1=['breakpoint', 'bp'], kw2=['sync'], cls='BreakpointCommands')
    def sync(self, args):
        """
        Sync breakpoint enable/disable state from debugger to device

            Syntax: breakpoint sync

        Breakpoint disable flags are cleared after resetting the device; this will
        restore their state to that known by the debugger.
        """
        breakpoint_list = self._repl.debugger().breakpoints().breakpoints()
        n = len(breakpoint_list)
        if n == 0:
            self._repl.debugger().msg_q(MsgLevel.INFO, '(No breakpoints to sync)')
            return
        elif n == 1:
            self._repl.debugger().msg_q(MsgLevel.INFO, 'Setting enable flag for 1 breakpoint...')
        else:
            self._repl.debugger().msg_q(MsgLevel.INFO, f'Setting enable flags for {n} breakpoints...')

        for bp in breakpoint_list:
            bp.sync()


    @CompoundCommand(kw1=['breakpoint', 'bp'], kw2=['new'], cls='BreakpointCommands')
    def create(self, args):
        """
        Create a new breakpoint

            Syntax: breakpoint new

        If supported by the device architecture, create a new breakpoint.
        """
        if not self._debugger.get_arch_conf("dynamic_breakpoints"):
            self._repl.debugger().msg_q(MsgLevel.ERR, "Device does not support breakpoint creation")
            return

        # TODO(aaron): Work out additional syntax requirements and implement.
        raise Exception("Unimplemented: `breakpoint new`")


