# (C) Copyright 2021 Aaron Kimball
#
# Stack analysis classes and routines.

import elftools.dwarf.callframe as callframe

import arduino_dbg.binutils as binutils
from arduino_dbg.term import MsgLevel

_debugger_methods = [
  "__vector_17",     # timer interrupt
  "__dbg_service",   # The debugger interactive service loop
]

class CallFrame(object):
    """
    Represents a frame on the call stack; generated in the debugger.get_backtrace()
    method.
    """

    def __init__(self, debugger, addr, sp):
        self._debugger = debugger

        self.addr = addr # $PC
        self.sp = sp
        self.name = None
        self.demangled = '???'
        self.frame_size = -1
        self.source_line = None
        self.inline_chain = []
        self.demangled_inline_chain = []
        self.sym = None

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

        self.frame_size = self._calculate_stack_frame_size()
        self._calculate_source_line(debugger.elf_name)
        self._demangle()

        self._unwound_registers = None # Cached map of register values pre-call (unwound)
        self._cfa = None               # Cached canonical frame address

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

        self.demangled_inline_chain = [ binutils.demangle(m) for m in self.inline_chain ]


    def _calculate_source_line(self, elf_name):
        """
        Calculate the source code file and line number from frame $PC.
        """
        self.source_line = binutils.pc_to_source_line(elf_name, self.addr)

    def _calculate_stack_frame_size(self):
        # TODO(aaron): Does self.sym have stack frame info attached we can use w/o going fishing?
        self.frame_size = stack_frame_size_for_method(self._debugger, self.addr, self.sym)
        return self.frame_size

    def get_cfa(self, regs_in):
        """
        Return the canonical frame address as calculated through the .debug_frame instructions.
        """
        if self._cfa is not None:
            return self._cfa

        self.unwind_registers(regs_in) # CFA calculated thru unwind process.
        return self._cfa # As saved by unwind_registers().

    def unwind_registers(self, regs_in):
        """
        Use the .debug_frame information in self.sym.frame_info to unwind the registers
        from this frame, returning the register state seen in the calling function
        immediately after this function/frame's return.

        The input to this method is a 'regs' dict from register names to values, as seen
        within this method at its active PC.

        The return value is a 'regs' dict with the same format & keys, with register
        values as seen by the calling method at that point.
        """
        if self._unwound_registers is not None:
            # We've already cached this value; return immediately.
            return self._unwound_registers

        # Get the architecture-specific register mapping from the configuration.
        stack_unwind_registers = self._debugger.get_arch_conf('stack_unwind_registers')
        num_general_regs = self._debugger.get_arch_conf('general_regs')
        has_sph = self._debugger.get_arch_conf('has_sph')
        push_word_len = self._debugger.get_arch_conf('push_word_len') # width of one PUSHed word.
        ret_addr_size = self._debugger.get_arch_conf('ret_addr_size') # width of return site addr on stack

        if not self.sym or not self.sym.frame_info:
            self._debugger.msg_q(MsgLevel.WARN,
                f"Warning: Could not unwind stack frame for method {self.name}.")
            return None

        pc = regs_in['PC']
        if pc is None:
            raise KeyError("No $PC value in input regs for to FrameInfo.unwind_registers()")

        # If the method is an ISR that saves SREG in prologue, we need to
        # monkeypatch the FDE to account for it, since gcc doesn't account for it when
        # generating .debug_frames.
        _patch_isr_debug_frames(self._debugger, self.sym, self.sym.frame_info, pc)

        decoded_info = self.sym.frame_info.get_decoded()
        cfi_table = decoded_info.table
        cfi_register_order = decoded_info.reg_order # Order in which registers appear in the table.

        rule_row = None
        for row in cfi_table:
            if pc > row['pc'] and (rule_row is None or rule_row['pc'] < row['pc']):
                # Most appropriate row we've yet iterated.
                rule_row = row

        if rule_row is None:
            # We broke into this method before any register moves or stack operations
            # were performed. (i.e., on the start $PC for the method itself.)
            # Just use the rule from the CIE, which declares the return value position.
            rule_row = self._debugger.get_frame_cie().get_decoded().table[-1]

        # The dict in 'best_row' now contains the current unwind info for the frame.
        row_pc = rule_row['pc']
        self._debugger.verboseprint(f"In method {self.sym.demangled} at PC {pc:04x}, use rowPC {row_pc:04x}")

        cfa_rule = rule_row['cfa']
        cfa_reg = stack_unwind_registers[cfa_rule.reg] # cfa gives us an index into the unwind
                                                       # reg names. Get the mapped-to reg name.
        if cfa_reg is None:
            self._debugger.msg_q(MsgLevel.ERROR,
                "Error: Unknown register mapping for r{cfa_reg} in CFA rule")
            return None

        cfa_base = regs_in[cfa_reg] # Read the mapped register to get the baseline for CFA

        if cfa_rule.reg < num_general_regs and has_sph:
            # cfa_reg points to e.g. r28, but $SP is 16 bits wide. Also use the next register.
            cfa_base = (regs_in[stack_unwind_registers[cfa_rule.reg + 1]] << 8) | (cfa_base & 0xFF)

        cfa_addr = cfa_base + cfa_rule.offset # We've established the call frame address.
                                              # This is where SP would point if the entire
                                              # frame went away via the epilogue + 'ret'.
        self._debugger.verboseprint(f'Canonical frame addr (CFA) = {cfa_addr:04x}')
        self._cfa = cfa_addr # Cache this for later.

        regs_out = regs_in.copy()

        regs_to_process = cfi_register_order.copy()
        regs_to_process.reverse() # LIFO.
        for reg_num in regs_to_process:
            reg_width = push_word_len

            rule = rule_row[reg_num] # type is RegisterRule
            reg_name = stack_unwind_registers[reg_num]

            if reg_name == 'LR' or reg_name == 'PC':
                reg_name = 'PC' # This return site will be assigned to PC after frame 'ret'.
                reg_width = ret_addr_size

            if rule.type == callframe.RegisterRule.UNDEFINED:
                continue # Nothing to do.
            elif rule.type == callframe.RegisterRule.SAME_VALUE:
                continue # We did not change this register value.
            elif rule.type == callframe.RegisterRule.OFFSET:
                # We've got an offset from the CFA; load the value at that memory address into
                # the assigned register.
                data = self._debugger.get_sram(cfa_addr + rule.arg, reg_width)
                if reg_name == 'PC':
                    # AVR: For $PC, swap the order of the two bytes retrieved, LSH the result by 1.
                    data = (((data & 0xFF) << 8) | ((data >> 8) & 0xFF)) << 1;
                regs_out[reg_name] = data
                self._debugger.verboseprint(
                    f'{reg_name}    <- LD({(cfa_addr + rule.arg):x}) (CFA+{rule.arg:x}) ' + \
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
                self._debugger.msg_q(MsgLevel.ERR,
                    "Error: Cannot process EXPRESSION register rule")
                return None
            elif rule.type == callframe.RegisterRule.VAL_EXPRESSION:
                self._debugger.msg_q(MsgLevel.ERR,
                    "Error: Cannot process VAL_EXPRESSION register rule")
                return None
            elif rule.type == callframe.RegisterRule.ARCHITECTURAL:
                self._debugger.msg_q(MsgLevel.ERR,
                    "Error: Cannot process architecture-specific register rule")
                return None

        regs_out['SP'] = cfa_addr # As established earlier.

        # TODO(aaron): gcc doesn't regard 'SREG' as unwindable; there won't be instructions on
        # how to restore the prior version of it, if it was saved within the method. So the
        # regs_in.copy() will include the child frame's SREG as-is.

        self._unwound_registers = regs_out # Cache for reuse if necessary.
        return regs_out

def _patch_isr_debug_frames(debugger, sym, frame_info, pc):
    if sym.isr_frame_ok:
        return # Already handled / not an issue for this method.

    sreg_save_sequence = debugger.get_arch_conf("GCC_ISR_SREG_SAVE_OPS")
    if not sreg_save_sequence:
        return # Not an issue for this architecture.

    fn_body = debugger.image_for_symbol(sym.name)
    default_fetch_width = debugger.get_arch_conf("default_op_width") # standard instruction decode size

    fn_start_pc = sym.addr
    fn_size = sym.size
    fn_end_pc = fn_start_pc + fn_size

    frame_table = frame_info.get_decoded().table
    last_prologue_pc = frame_table[-1]['pc']

    # Scan the prologue only, not the entire method.
    last_scan_pc = min(last_prologue_pc, fn_end_pc)

    patch_pc = None
    for virt_pc in range(fn_start_pc, last_scan_pc, default_fetch_width):
        sliding_window = fn_body[virt_pc - fn_start_pc : virt_pc - fn_start_pc + len(sreg_save_sequence)]
        if sliding_window == sreg_save_sequence:
            # We found the SREG save sequence.
            patch_pc = virt_pc + len(sreg_save_sequence)
            break

    if patch_pc is None:
        # No SREG save in prologue of this method.
        sym.isr_frame_ok = True
        return

    # For all rows where row['pc'] >= patch_pc:
    # - Adjust CFARule to have offset += 1
    # - Any new OFFSET RegisterRule gets an offset -= 1
    # - Any REGISTER RegisterRule is no-op.
    # - Any other kind of RegRule we don't know how to adjust, and should fail.
    #
    # This is shallow-copied, so we shouldn't need to modify too many RegisterRules.
    # But we want to adjust each CFARule exactly once. Keep a list of 'seen' objects
    # and don't modify more than once
    # TODO(aaron): what if it sets up a frame ptr in Y and shifts the CFARule?
    debugger.verboseprint(
        f"Adjusting frame table for PC >= {patch_pc:04x} in method {sym.name} due to $SREG save bug.")

    seen_rules = {} # Keep track of rules already visited

    for row in frame_table:
        row_pc = row['pc']
        if row_pc >= patch_pc:
            # $SP offsets created at / after this point are affected by SREG push
            # and need a further offset.
            for (reg, rule) in row.items():
                if reg == 'pc':
                    continue # Not a real rule.
                if seen_rules.get(rule) is not None:
                    continue # Rule already seen/adjusted.

                if isinstance(rule, callframe.CFARule):
                    if rule.offset is not None:
                        # Add 1 to CFA offset because the register is below the CFA, and we
                        # calculate the CFA relative to the register in question.
                        rule.offset += 1
                    elif rule.expr is not None:
                        debugger.msg_q(MsgLevel.WARN,
                            f"Warning: CFA Rule at PC {row_pc:04x} has DWARF expr; unsupported")
                elif isinstance(rule, callframe.RegisterRule):
                    if rule.type == callframe.RegisterRule.UNDEFINED:
                        pass # No modification needed.
                    elif rule.type == callframe.RegisterRule.SAME_VALUE:
                        pass # No modification needed.
                    elif rule.type == callframe.RegisterRule.OFFSET:
                        # Adjust the offset by subtracting 1 for SREG's position on the stack.
                        # We subtract here (vs add) because the data is below the CFA, and
                        # we calculate this register's position relative to the CFA.
                        rule.arg -= 1
                    elif rule.type == callframe.RegisterRule.VAL_OFFSET:
                        # Don't have an example of one of these, so I don't know if we need to
                        # adjust, or in which direction.
                        debugger.msg_q(MsgLevel.WARN,
                            f"Warning: Got a VAL_OFFSET for reg {reg}; does it need an offset?!??")
                    elif rule.type == callframe.RegisterRule.REGISTER:
                        pass # No modification needed.
                    elif rule.type == callframe.RegisterRule.EXPRESSION:
                        debugger.msg_q(MsgLevel.WARN,
                            f'Warning: Reg rule at PC {row_pc:04x}, reg {reg} is unsupported type EXPR')
                    elif rule.type == callframe.RegisterRule.VAL_EXPRESSION:
                        debugger.msg_q(MsgLevel.WARN,
                            f'Warning: Reg rule at PC {row_pc:04x}, reg {reg} is unsupported type VAL_EXPR')
                    elif rule.type == callframe.RegisterRule.ARCHITECTURAL:
                        debugger.msg_q(MsgLevel.WARN,
                            f'Warning: Reg rule at PC {row_pc:04x}, reg {reg} is unsupported type ARCH')
                    else:
                        debugger.msg_q(MsgLevel.WARN,
                            f'Warning: Do not know how to process reg rule type={rule.type}')
                else:
                    # No idea how to process this...
                    debugger.msg_q(MsgLevel.WARN,
                        f"Warning: Got rule for register {reg} of instance {rule.__class__}")

                seen_rules[rule] = True # Mark rule as seen so we don't double-process.
        else:
            # $SP offsets not yet affected by SREG push at this point in the prologue.
            # Add all members of this row to the seen rule list so we preserve them as-is.
            for (reg, rule) in row.items():
                if reg == 'pc':
                    continue # Not a real rule.
                seen_rules[rule] = True

    # Now that the frame_table has been corrected, don't perform this procedure on this
    # method again.
    sym.isr_frame_ok = True


def get_stack_autoskip_count(debugger):
    """
        Return the number of bytes in the stack to skip when dumping the stack
        to the user console. This is the number of bytes required to skip all
        _debugger_methods[] entries on the top of the call stack.
    """
    regs = debugger.get_registers()
    sp = regs["SP"]
    pc = regs["PC"]

    ret_addr_size = debugger.get_arch_conf("ret_addr_size")

    frames = debugger.get_backtrace(limit=len(_debugger_methods))
    for frame in frames:
        try:
            _debugger_methods.index(frame['name'])
        except ValueError:
            # This frame is not part of the debugger service, it's a real frame.
            return frame['sp'] - sp # Skip count == diff between this frame's SP and real SP

    # All the debugger methods are on the stack. Last frame holds the key: its offset
    # from the current stack pointer /plus/ the frame size & retaddr
    last_frame = frames[len(_debugger_methods) - 1]
    return (last_frame['sp'] - sp) + last_frame['frame_size'] + ret_addr_size


def stack_frame_size_for_method(debugger, pc, method_sym):
    """
        Given a program counter (PC) somewhere within the body of `method_sym`, determine
        the size of the current stack frame at that point and return it.

        i.e., if SP is 'x' and this method returns 4, then 4 bytes of stack RAM have been
        filled by the method (x+1..x+4) and the (2 byte AVR) return address is at
        x+5..x+6.
    """

    if method_sym is None:
        debugger.msg_q(MsgLevel.ERR,
            f"Error: No function symbol for method: {method_name}; method frame size = ???")
        return None

    # Pull opcode details from architecture configuration.
    # opcode records contain fields: name, OPCODE, MASK, width, decoder
    prologue_opcodes = debugger.get_arch_conf("prologue_opcodes")

    push_word_len = debugger.get_arch_conf("push_word_len") # nr of bytes a PUSH adds to the stack.
    default_fetch_width = debugger.get_arch_conf("default_op_width") # standard instruction decode size
    has_sph = debugger.get_arch_conf("has_sph") # True if we have a 16-bit $SP ($SPH:$SPL)

    spl_port = debugger.get_arch_conf("SPL_PORT") # Port for IN Rd, <port> to read SPL
    if has_sph:
        sph_port = debugger.get_arch_conf("SPH_PORT") # Port for IN Rd, <port> to read SPH
    else:
        sph_port = None

    fn_body = debugger.image_for_symbol(method_sym.name)

    fn_start_pc = method_sym.addr
    fn_size = method_sym.size

    debugger.verboseprint(f"Getting frame size for method {method_sym.name} (@PC {pc:04x})")
    debugger.verboseprint(f"start addr {fn_start_pc:04x}, size {fn_size} bytes")

    # Walk through the instructions of the method until we reach the end of the prologue
    # or the current PC. Track the stack size through this point. We believe we are done
    # with the prologue when we encounter an instruction that is not in the `prologue_opcodes`
    # list.
    #
    # During this time we operate a state machine that understands how certain
    # instructions or patterns of instructions modify the frame size.
    #
    # TODO(aaron): This will not properly backtrace if the method performs PUSH operations
    # (or modifies SP directly with IN -> {SUBI, ADDI} -> OUT to SPL/SPH) after the method
    # prologue. Without knowledge of the basic block / control flow structure within the
    # method (or the path withn those taken by the PC from prologue to its current point)
    # we can't just safely read linearly. If we do need to debug methods with this kind of
    # operation, we need to be able to rely on an explicit frame pointer we can identify
    # in the prologue.
    depth = 0
    virt_pc = fn_start_pc

    # State machine to detect IN SPL/SPH -> SBIW/SUBI -> OUT SPL/SPH instruction sequence pattern
    # that preallocates 1 or more bytes of space on the stack for locals.
    #
    # TODO(aaron): This is AVR-specific. Can we parameterize at levels smaller than this entire
    # method?
    IO_SUB_PATTERN_NONE  = 0
    IO_SUB_PATTERN_IN_1  = 1 # Read one of SPL/SPH
    IO_SUB_PATTERN_IN_2  = 2 # Read both of SPL/SPH
    IO_SUB_PATTERN_SUB   = 3 # Subtracted from SPL/SPH (via SBIW / SUBI Rd, i)
    IO_SUB_PATTERN_OUT_1 = 4 # Wrote back one of SPL/SPH
    IO_SUB_PATTERN_DONE  = 5 # After writing back both (or 1 if !has_sph), lock in, then back to pattern_none.

    spl_active_reg = None
    sph_active_reg = None
    possible_offset = 0
    io_sub_seq_state = IO_SUB_PATTERN_NONE # Not currently in this pattern.

    while virt_pc < (fn_start_pc + fn_size) and virt_pc < pc:
        width = default_fetch_width
        op = int.from_bytes(fn_body[virt_pc - fn_start_pc : virt_pc - fn_start_pc + width],
            "little", signed=False)
        #print(f'vpc {virt_pc:04x} (w={width}) -- op {op:02x} {op:016b}')

        is_prologue = False # Don't yet know if this instruction is part of the prologue

        for opcode_rec in prologue_opcodes:
            loop_op = op
            loop_width = width

            if opcode_rec['width'] != default_fetch_width:
                # Try to decode more than the standard fetch width at once.
                loop_width = opcode_rec['width']
                this_op = int.from_bytes(
                    fn_body[virt_pc - fn_start_pc : virt_pc - fn_start_pc + loop_width],
                    "little", signed=False)

            if (loop_op & opcode_rec['MASK']) != opcode_rec['OPCODE']:
                # It's not this opcode_rec
                continue

            # The `loop_op` instruction is confirmed to match opcode_rec.
            # This instruction confirmed as a valid prologue opcode.
            is_prologue = True

            # Certain opcodes modify our frame-size calculating state machine.
            if opcode_rec['name'] == 'pop':
                depth -= push_word_len
            elif opcode_rec['name'] == 'push':
                depth += push_word_len
            elif opcode_rec['name'] == 'in':
                (port, rd) = opcode_rec['decoder'](loop_op)
                if port == spl_port:
                    spl_active_reg = rd # We've loaded $SPL into Rd.
                    possible_offset = 0 # Reset possible_offset since we can't have SBIW'd yet.
                    if io_sub_seq_state < IO_SUB_PATTERN_IN_2:
                        # Advance state machine by 1
                        io_sub_seq_state += 1
                    else:
                        # Redundant `in` (?) locks us into IN_2 state.
                        io_sub_seq_state = IO_SUB_PATTERN_IN_2

                    if not has_sph:
                        # Skip _IN_1 state; there is no $SPH so we've read the whole SP.
                        io_sub_seq_state = IO_SUB_PATTERN_IN_2
                elif has_sph and port == sph_port:
                    sph_active_reg = rd # We've loaded $SPH into Rd.
                    possible_offset = 0 # Reset possible_offset since we can't have SBIW'd yet.
                    if io_sub_seq_state < IO_SUB_PATTERN_IN_2:
                        # Advance state machine by 1
                        io_sub_seq_state += 1
                    else:
                        # Redundant `in` (?) locks us into IN_2 state.
                        io_sub_seq_state = IO_SUB_PATTERN_IN_2
                else:
                    # We read some other register port (e.g., SREG). Irrelevant to state
                    # machine.
                    pass
            elif opcode_rec['name'] == 'sbiw':
                (rd, imm) = opcode_rec['decoder'](loop_op)
                if rd == spl_active_reg and io_sub_seq_state == IO_SUB_PATTERN_IN_2:
                    # For registers holding SPH/SPL, (SPH:SPL) <-- (SPH:SPL) - imm
                    io_sub_seq_state = IO_SUB_PATTERN_SUB
                    possible_offset = imm
            elif opcode_rec['name'] == 'subi':
                (rd, imm) = opcode_rec['decoder'](loop_op)
                if rd == spl_active_reg and io_sub_seq_state == IO_SUB_PATTERN_IN_2:
                    # For register holding SPL, SPL <-- SPL - imm
                    io_sub_seq_state = IO_SUB_PATTERN_SUB
                    possible_offset = imm
            elif opcode_rec['name'] == 'out':
                (port, rd) = opcode_rec['decoder'](loop_op)
                if io_sub_seq_state >= IO_SUB_PATTERN_SUB:
                    # We either just saw the SBIW or wrote one of the two ports.
                    if port == spl_port and rd == spl_active_reg:
                        io_sub_seq_state += 1 # Wrote back to $SPL
                    elif has_sph and port == sph_port and rd == sph_active_reg:
                        io_sub_seq_state += 1

                    if io_sub_seq_state == IO_SUB_PATTERN_OUT_1 and not has_sph:
                        io_sub_seq_state += 1 # Advance to _DONE; no $SPH to write.

                    if io_sub_seq_state == IO_SUB_PATTERN_DONE:
                        # We have completed the pattern
                        debugger.verboseprint(f"Direct SP adjustment of {possible_offset}")
                        depth += possible_offset # possible_offset confirmed as frame ptr offset

                        # Reset state machine.
                        io_sub_seq_state = IO_SUB_PATTERN_NONE
                        possible_offset = 0
                        spl_active_reg = None
                        sph_active_reg = None

            virt_pc += loop_width # Advance virtual $PC past this instruction
            break # Break out of cycle of decode attempts for this instruction.

        if not is_prologue:
            # We tested all possible prologue opcodes and this instruction isn't one of 'em.
            # We've ran past the end of the prologue and established the frame size.
            break

    debugger.verboseprint(f"Established frame_size={depth}")
    return depth


def stack_frame_size_by_pc(debugger, pc):
    """
        Given a program counter (PC), determine what method we're in and return the size
        of the stack frame
    """
    method = debugger.function_sym_by_pc(pc)
    return stack_frame_size_for_method(debugger, pc, method)


