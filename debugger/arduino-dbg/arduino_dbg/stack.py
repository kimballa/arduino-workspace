# (C) Copyright 2021 Aaron Kimball
#
# Stack analysis classes and routines.

import elftools.dwarf.callframe as callframe

import arduino_dbg.binutils as binutils
from arduino_dbg.term import MsgLevel
import arduino_dbg.term as term

_debugger_methods = [
  "__vector_17",     # AVR timer interrupt
  "TC4_Handler",     # SAMD51 timer interrupt
  "__dbg_service",   # The debugger interactive service loop
]


class CallFrame(object):
    """
    Represents a frame on the call stack; generated in the debugger.get_backtrace()
    method.
    """

    def __init__(self, debugger, addr, sp, regs_in=None):
        self._debugger = debugger

        self.addr = addr  # $PC
        self.sp = sp
        self.name = None
        self.demangled = '???'
        self.frame_size = None
        self.source_line = None
        self.inline_chain = []
        self.demangled_inline_chain = []
        self.sym = None

        self.break_registers = regs_in  # Cached map of register values at breakpoint in backtrace.
        self.unwound_registers = None   # Cached map of register values pre-call (unwound)
        self.cfa = None                 # Cached canonical frame address

        func_sym = debugger.function_sym_by_pc(addr)
        if func_sym is None:
            debugger.msg_q(MsgLevel.WARN, f"Warning: could not resolve $PC={addr:#04x} to method symbol")
            return
        else:
            self.name = func_sym.name
            self.sym = func_sym

        # With a resolved method name available, complete the stack frame record.

        # Look up info about method inlining; the decoded name for $PC may logically
        # be within more methods.
        self.inline_chain = debugger.get_debug_info().getMethodsForPC(addr)

        self._calculate_source_line(debugger.elf_name)
        self._demangle()

        if regs_in is not None:
            # If register snapshot is available at the point $PC, calculate unwound
            # registers (reg snapshot in this method's caller at its resume $PC).
            self.unwind_registers(regs_in)  # Set self.unwound_registers.

        self._calculate_stack_frame_size(regs_in)  # Set self.frame_size.


    def __repr__(self):
        out = f"{self.addr:04x}: {self.demangled}"

        if self.source_line:
            out += f'  ({self.source_line})'

        if len(self.demangled_inline_chain) > 1:
            out += f"\n    Inlined method calls: {' in '.join(self.demangled_inline_chain)}"

        return out

    def _demangle(self):
        """
        Demangle method names.
        """
        if self.sym:
            self.demangled = self.sym.demangled
        else:
            self.demangled = binutils.demangle(self.name) or '???'

        self.demangled_inline_chain = list(map(binutils.demangle, self.inline_chain))


    def _calculate_source_line(self, elf_name):
        """
        Calculate the source code file and line number from frame $PC.
        """
        self.source_line = binutils.pc_to_source_line(elf_name, self.addr)

    def _calculate_stack_frame_size(self, regs_in):
        """
        Given a program counter ($PC, held in self.addr) somewhere within the body of `self.sym`,
        determine the size of the current stack frame at that point and return it.

        `regs_in` holds the register snapshot at the current $PC.
        """
        if self.sym is None:
            self._debugger.msg_q(
                MsgLevel.ERR,
                "Error: No function symbol for method; method frame size = ???")
            self.frame_size = None
        else:
            self.frame_size = self._debugger.arch_iface.stack_frame_size(self, regs_in)

        return self.frame_size

    def get_cfa(self, regs_in):
        """
        Return the canonical frame address as calculated through the .debug_frame instructions.
        """
        if self.cfa is not None:
            return self.cfa

        self.unwind_registers(regs_in)  # CFA calculated thru unwind process.
        return self.cfa  # As saved by unwind_registers().

    def unwind_registers(self, regs_in):
        """
        Use the .debug_frame information in self.sym.frame_info to unwind the registers
        from this frame, returning the register state seen in the calling function
        immediately after this function/frame's return.

        The input to this method is a 'regs' dict from register names to values, as seen
        within this method at its active PC. If this is None, then the 'break_registers'
        field set in the constructor is used instead.

        The return value is a 'regs' dict with the same format & keys, with register
        values as seen by the calling method at that point.
        """
        if self.unwound_registers is not None:
            # We've already cached this value; return immediately.
            return self.unwound_registers

        if regs_in is None:
            regs_in = self.break_registers  # live register set already provided in c'tor.

        # Get the architecture-specific register mapping from the configuration.
        abi_real_link_register = self._debugger.get_arch_conf('abi_uses_link_register')
        stack_unwind_registers = self._debugger.get_arch_conf('stack_unwind_registers')
        num_general_regs = self._debugger.get_arch_conf('general_regs')
        push_word_len = self._debugger.get_arch_conf('push_word_len')  # width of one PUSHed word.
        ret_addr_size = self._debugger.get_arch_conf('ret_addr_size')  # width of return site addr on stack

        reg_width = self._debugger.arch_iface.reg_width_bytes()
        reg_word_mask = self._debugger.arch_iface.reg_word_mask()  # Bitmask for reg_width bytes.
        sp_width = self._debugger.arch_iface.sp_width_bytes()  # on AVR, SP is wider than a gen reg.

        frame_cie = self._debugger.get_frame_cie()  # CIE (common info entry) for this ELF
        return_addr_reg = frame_cie['return_address_register']
        has_unwound_pc = False  # Set to true once $PC is updated.

        if not self.sym or not self.sym.frame_info:
            self._debugger.msg_q(MsgLevel.WARN,
                                 f"Warning: Could not unwind stack frame for method {self.name}.")
            return None

        pc = regs_in['PC']
        if pc is None:
            raise KeyError("No $PC value in input regs for to FrameInfo.unwind_registers()")

        # In some cases (e.g., ISRs on AVR that save SREG in prologue), we need to
        # monkeypatch the FDE to account for all the pushed data, since due to a bug
        # gcc may not account for it when generating .debug_frames. Use arch-specific
        # debug_frame patching method.
        if not self.sym.isr_frame_ok:
            self._debugger.arch_iface.patch_debug_frame(self.sym, self.sym.frame_info, pc)

        decoded_info = self.sym.frame_info.get_decoded()
        cfi_table = decoded_info.table
        cfi_register_order = decoded_info.reg_order  # Order in which registers appear in the table.

        rule_row = None
        for row in cfi_table:
            if pc > row['pc'] and (rule_row is None or rule_row['pc'] < row['pc']):
                # Most appropriate row we've yet iterated.
                rule_row = row

        if rule_row is None:
            # We broke into this method before any register moves or stack operations
            # were performed. (i.e., on the start $PC for the method itself.)
            # Just use the rule from the CIE, which declares the return value position.
            rule_row = frame_cie.get_decoded().table[-1]

        # The dict in 'rule_row' now contains the current unwind info for the frame.
        row_pc = rule_row['pc']
        self._debugger.verboseprint(
            f"\nIn method {self.sym.demangled} at PC {pc:04x}, use rowPC {row_pc:04x}")

        cfa_rule = rule_row['cfa']
        cfa_reg = stack_unwind_registers[cfa_rule.reg]  # cfa gives us an index into the unwind
                                                        # reg names. Get the mapped-to reg name.
        if cfa_reg is None:
            self._debugger.msg_q(MsgLevel.ERROR,
                                 "Error: Unknown register mapping for r{cfa_reg} in CFA rule")
            return None

        cfa_base = regs_in[cfa_reg]  # Read the mapped register to get the baseline for CFA

        if cfa_rule.reg < num_general_regs and sp_width > reg_width:
            # cfa_reg points to e.g. r28, but $SP is wider than r28: also use the next register.
            assert sp_width == 2 * reg_width
            cfa_base = (regs_in[stack_unwind_registers[cfa_rule.reg + 1]] << (8 * reg_width)) | \
                (cfa_base & reg_word_mask)

        cfa_addr = cfa_base + cfa_rule.offset   # We've established the call frame address.
                                                # This is where SP would point if the entire
                                                # frame went away via the epilogue + 'ret'.
        self.cfa = cfa_addr  # Cache this for later.

        regs_out = regs_in.copy()

        if self._debugger.get_conf("dbg.verbose"):
            self._debugger.verboseprint(f'Canonical frame addr (CFA) = {cfa_addr:04x}')
            self._debugger.verboseprint('Return address register: ', return_addr_reg)
            self._debugger.verboseprint('')
            self._debugger.verboseprint('Input registers:')
            self._debugger.verboseprint(term.fmt_registers(regs_in, reg_width, sp_width))
            self._debugger.verboseprint('')

            self._debugger.verboseprint('CFI table: ')
            for row in cfi_table:
                row_pc = row['pc']
                self._debugger.verboseprint(f'    PC >= 0x{row_pc:x}:    {row}')

            self._debugger.verboseprint('')
            self._debugger.verboseprint('Rule row: ', rule_row)

        regs_to_process = cfi_register_order.copy()
        regs_to_process.reverse()  # LIFO.
        self._debugger.verboseprint('regs_to_process: ', regs_to_process)
        for reg_num in regs_to_process:
            reg_width = push_word_len

            self._debugger.verboseprint('Processing register number: ', reg_num)

            try:
                rule = rule_row[reg_num]  # type is RegisterRule
            except KeyError:
                # We do not have a rule to process this register. Assume it's unchanged
                # from prior value. (gcc for arm7/thumb seems to omit no-op rules to save space?)
                continue

            reg_name = stack_unwind_registers[reg_num]
            self._debugger.verboseprint('Reg name: ', reg_name)
            self._debugger.verboseprint('Applying rule: ', rule)

            if not abi_real_link_register and reg_name == 'LR':
                # Special-case $LR for e.g. AVR -- CFI record defines return addr site through
                # an "unwind register" we call $LR but this does not correspond to a real $LR.
                # In which case, we actually want to assign its unwind result directly to $PC.
                reg_name = 'PC'  # This return site will be assigned to PC after frame 'ret'.

                # TODO(aaron): Should this be checking for 'LR' in our reg_name? Or should
                # we be checking for reg_num == return_addr_reg as in the "real" handler after
                # the end of the main rule.type switchcase below?

            if reg_name == 'PC' or reg_name == 'LR' or reg_num == return_addr_reg:
                # $LR / $PC assignment is definitionally `ret_addr_size` bytes wide even
                # if standard register width is smaller (e.g. on AVR)
                reg_width = ret_addr_size

            if rule.type == callframe.RegisterRule.UNDEFINED:
                pass  # Nothing to do.
            elif rule.type == callframe.RegisterRule.SAME_VALUE:
                pass  # We did not change this register value.
            elif rule.type == callframe.RegisterRule.OFFSET:
                # We've got an offset from the CFA; load the value at that memory address into
                # the assigned register.
                data = self._debugger.get_sram(cfa_addr + rule.arg, reg_width)
                if reg_name == 'PC' or reg_name == 'LR':
                    data = self._debugger.arch_iface.mem_to_pc(data)
                regs_out[reg_name] = data
                self._debugger.verboseprint(
                    f'{reg_name}    <- LD(0x{(cfa_addr + rule.arg):x}) (CFA + {rule.arg:x}h) '
                    f'[= {regs_out[reg_name]:x} ]')
            elif rule.type == callframe.RegisterRule.VAL_OFFSET:
                # Based on https://dwarfstd.org/ShowIssue.php?issue=030812.2 I believe this
                # instruction says to say rule.reg += rule.arg (without referencing CFA)?
                regs_out[reg_name] = regs_in[reg_name] + rule.arg
                self._debugger.verboseprint(
                    f'{reg_name}    <- {reg_name} + {rule.arg:x} [= {regs_out[reg_name]:x} ]')
            elif rule.type == callframe.RegisterRule.REGISTER:
                # Copy one register to another: rDst <- rSrc
                reg_in_name = stack_unwind_registers[rule.arg]
                regs_out[reg_name] = regs_in[reg_in_name]
                self._debugger.verboseprint(
                    f'{reg_name}    <- {reg_in_name} [= {regs_out[reg_name]:x} ]')
            elif rule.type == callframe.RegisterRule.EXPRESSION:
                self._debugger.msg_q(
                    MsgLevel.ERR,
                    "Error: Cannot process EXPRESSION register rule")
                return None
            elif rule.type == callframe.RegisterRule.VAL_EXPRESSION:
                self._debugger.msg_q(
                    MsgLevel.ERR,
                    "Error: Cannot process VAL_EXPRESSION register rule")
                return None
            elif rule.type == callframe.RegisterRule.ARCHITECTURAL:
                self._debugger.msg_q(
                    MsgLevel.ERR,
                    "Error: Cannot process architecture-specific register rule")
                return None

            if reg_num == return_addr_reg and abi_real_link_register:
                # Now that we've processed the current register update... if this operation
                # restored the register that contained the return address (i.e., it's $LR),
                # then we also want to apply this value to $PC.
                regs_out['PC'] = regs_out[reg_name]
                has_unwound_pc = True  # $PC updated.
                self._debugger.verboseprint(
                    f'** $PC    <- {reg_name} [= {regs_out[reg_name]:x} ]')

            if reg_name == 'PC':
                has_unwound_pc = True  # $PC updated.

        regs_out['SP'] = cfa_addr  # As established earlier.

        if not has_unwound_pc and abi_real_link_register:
            # We did not explicitly update the $PC register based on stack unwind operations.
            # However, we have a true link register available to us. We should update the $PC
            # now. We can encounter this situation if we experience an interrupt immediately
            # within the prologue of a method before entry stacking operations have occured.
            # The $LR will hold the return addr and will not have itself been stacked yet.
            regs_out['PC'] = regs_out[stack_unwind_registers[return_addr_reg]]
            has_unwound_pc = True
            self._debugger.verboseprint(f'** Final $PC from link register: {regs_out["PC"]:x}')

        if self._debugger.arch_iface.is_exception_return(regs_out['PC']):
            # We are returning from an exception stack frame onto the normal program stack.
            # The hardware has performed special stacking operations before entering the
            # exception handler (and thus not part of the exc handler's CFI) and we must
            # now do architecture-specific destacking of those registers.
            self._debugger.verboseprint("Exception return detected -- unwinding exception stacking")
            regs_out = self._debugger.arch_iface.unwind_exception_registers(regs_out)

        # TODO(aaron): [AVR] gcc doesn't regard 'SREG' as unwindable; there won't be instructions
        # on how to restore the prior version of it, if it was saved within the method. So the
        # regs_in.copy() will include the child frame's SREG as-is.

        # Perform any final arch-specific postprocessing on register unwind operation.
        self._debugger.arch_iface.finish_register_unwind(regs_out)

        self.unwound_registers = regs_out  # Cache for reuse if necessary.
        return regs_out



def get_stack_autoskip_count(debugger):
    """
    Return the number of bytes in the stack to skip when dumping the stack
    to the user console. This is the number of bytes required to skip all
    _debugger_methods[] entries on the top of the call stack.
    """
    regs = debugger.get_registers()
    sp = regs["SP"]

    frames = debugger.get_backtrace(limit=len(_debugger_methods) + 1)
    for frame in frames:
        if frame.name not in _debugger_methods:
            # This frame is not part of the debugger service, it's a real frame.
            # Skip count == diff between this frame's SP and real SP
            return frame.break_registers['SP'] - sp

    # The _debugger_methods list contains methods that are mutually exclusive;
    # only a subset will ever be appropriate for a given architecture. We shouldn't get
    # here, because it implies the debugger's stack frames are the entire stack; not possible.
    raise RuntimeError("No viable stack frame found")


