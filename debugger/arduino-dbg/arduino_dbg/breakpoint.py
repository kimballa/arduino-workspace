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

    `bp` is a synonym for `breakpoint` in repl.

Future work:
    breakpoint create $PC   - create a new breakpoint at $PC.
                              (Can we do it by `source.cpp:line` too?)
    step                    - Run one opcode (line?)
    step return             - Run all opcodes thru end of this method/call frame.
"""

import arduino_dbg.binutils as binutils


class BreakpointDatabase(object)
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

    def __repr__(self):
        bp_strs = list(map(repr, self._breakpoints)) # Format breakpoint strs
        nums = list(map(lambda i: f'#{i}. ', range(0, len(bp_strs)))) # Format "#0. ", "#1. ", ...
        lines = list(map(''.join, zip(nums, bp_strs))) # connect those into 1 str/line.
        return '\n'.join(lines)


    def parse_pause_flags(self, pause_line):
        """
        When the sketch pauses, it sends a line of the form:
            Paused <bitNum:x> <bitfieldAddr:x>

        ... memorize these two numbers to attach to the next regi
        """
        should this be in this file? Or move back to Debugger?

    def register_bp(self, pc):
        """
        Register a new breakpoint; either created by client or as we
        encounter it live in the set program.
        """

        if pc in self._pc_to_bp:
            return # Already registered.

        bp = Breakpoint(self._debugger, pc)
        self._breakpoints.append(bp)
        self._pc_to_bp[pc] = bp

    def toggle_bp_by_idx(self, idx, enabled):
        """
        Set breakpoint enabled state for the idx'th entry in our database.
        """
        if idx >= len(self._breakpoints):
            raise IndexError(f'No such breakpoint id #{idx}')

        self._breakpoints[idx].enabled = enabled

    def toggle_bp_by_pc(self, pc, enabled):
        """
        Set breakpoint enabled state for bp at $PC.
        """
        if pc not in self._pc_to_bp:
            raise KeyError(f'No known breakpoint at $PC={pc:04x}')

        self._pc_to_bp[pc].enabled = enabled

    def get_bp_for_pc(self, pc):
        """
        Return the breakpoint known at $PC or None if no such known breakpoint.
        """

        if pc in self._pc_to_bp:
            return self._pc_to_bp[pc]
        else
            return None

    def get_bp(self, idx):
        """
        Return the n'th breakpoint or None if overrunning the list length.
        """
        if idx >= len(self._breakpoints):
            return None

        return self._breakpoints[idx]

    def forget(self, idx)
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

    def __init__(self, debugger, pc, is_dynamic=False):
        self.pc = pc
        self.is_dynamic = is_dynamic # True if we created from client; False if static in prgm.
        self.enabled = True
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

    def __repr__(self):
        s = f'$PC={self.pc:04x}:  '

        if len(self.demangled_inline_chain) > 1:
            s += ' inlined in '.join(self.demangled_inline_chain)
        else:
            s += '{self.demangled}'

        if self.source_line:
            s += f'  ({self.source_line})'

        return s
