# (C) Copyright 2021 Aaron Kimball
#
# Stack analysis classes and routines.

import arduino_dbg.binutils as binutils
import arduino_dbg.types as types

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
        self.name = '???'
        self.demangled = '???'
        self.frame_size = -1
        self.source_line = None
        self.inline_chain = []
        self.demangled_inline_chain = []

        func_name = debugger.function_sym_by_pc(addr)
        if func_name is None:
            print(f"Warning: could not resolve $PC={addr:#04x} to method symbol")
            return
        else:
            self.name = func_name

        # With a resolved method name available, complete the stack frame record.

        # Look up info about method inlining; the decoded name for $PC may logically
        # be within more methods.
        self.inline_chain = types.getMethodsForPC(addr)

        self.frame_size = self._calculate_stack_frame_size()
        self._calculate_source_line(debugger.elf_name)
        self._demangle()

    def _demangle(self):
        """
        Demangle method names.
        """
        self.demangled = binutils.demangle(self.name)
        self.demangled_inline_chain = [ binutils.demangle(m) for m in self.inline_chain ]


    def _calculate_source_line(self, elf_name):
        """
        Calculate the source code file and line number from frame $PC.
        """
        self.source_line = binutils.pc_to_source_line(elf_name, self.addr)

    def _calculate_stack_frame_size(self):
        self.frame_size = stack_frame_size_for_method(self._debugger, self.addr, self.name)
        return self.frame_size


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


def stack_frame_size_for_method(debugger, pc, method_name):
    """
        Given a program counter (PC) somewhere within the body of `method_name`, determine
        the size of the current stack frame at that point and return it.

        i.e., if SP is 'x' and this method returns 4, then 4 bytes of stack RAM have been
        filled by the method (x+1..x+4) and the (2 byte AVR) return address is at
        x+5..x+6.
    """

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

    fn_body = debugger.image_for_symbol(method_name)
    fn_sym = debugger.lookup_sym(method_name)
    if fn_sym is None:
        print(f"Error: No function symbol for method: {method_name}; method frame size = ???")
        return None

    fn_start_pc = fn_sym['addr']
    fn_size = fn_sym['size']

    debugger.verboseprint(f"Getting frame size for method {method_name} (@PC {pc:04x})")
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
    method_name = debugger.function_sym_by_pc(pc)
    return stack_frame_size_for_method(debugger, pc, method_name)


