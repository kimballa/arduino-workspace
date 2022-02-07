# (c) Copyright 2022 Aaron Kimball

"""
AVR-specific architecture interface.
"""

import arduino_dbg.arch as arch


@arch.iface
class AVRArchInterface(arch.ArchInterface):
    """
    AVR-specific implementation of ArchInterface.
    """

    def __init__(self, debugger):
        super().__init__(debugger)

    def true_pc(self, mem_pc):
        # AVR: PC stored in memory is only PC[15:1]. Align it left by 1 bit so that
        # we see a full 16-bit (Flash segment) memory address. Low-order bit is always zero.
        return mem_pc << 1

    def stack_frame_size_for_prologue(self, pc, method_sym):
        """
        Given a program counter ($PC) somewhere within the body of `method_sym`, determine
        the size of the current stack frame at that point and return it.

        i.e., if SP is 'x' and this method returns 4, then 4 bytes of stack RAM have been
        filled by the method (x+1..x+4) and the (2 byte AVR) return address is at
        x+5..x+6.

        This method uses prologue analysis to determine the size of the stack frame: by
        analyzing the disassembly of the method containing the indicated $PC, we establish
        the size of the stack frame in question.

        NOTE: While the opcodes to analyze are parameterized in prologue_opcodes array below,
        the pattern recognition state machine implemented here is AVR-specific.
        """
        debugger = self.debugger

        # Architecture-specific array of prologue opcodes defined in `prologue_opcodes`
        # at the bottom of this module.
        # opcode records contain fields: name, OPCODE, MASK, width, decoder

        push_word_len = debugger.get_arch_conf("push_word_len")  # nr of bytes a PUSH adds to the stack.
        default_fetch_width = debugger.get_arch_conf("default_op_width")  # standard instruction decode size
        has_sph = debugger.get_arch_conf("has_sph")  # True if we have a 16-bit $SP ($SPH:$SPL)

        spl_port = debugger.get_arch_conf("SPL_PORT")  # Port for IN Rd, <port> to read SPL
        if has_sph:
            sph_port = debugger.get_arch_conf("SPH_PORT")  # Port for IN Rd, <port> to read SPH
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
        IO_SUB_PATTERN_NONE = 0
        IO_SUB_PATTERN_IN_1 = 1   # noqa: F841 (Read one of SPL/SPH)
        IO_SUB_PATTERN_IN_2 = 2   # Read both of SPL/SPH
        IO_SUB_PATTERN_SUB = 3    # Subtracted from SPL/SPH (via SBIW / SUBI Rd, i)
        IO_SUB_PATTERN_OUT_1 = 4  # Wrote back one of SPL/SPH
        IO_SUB_PATTERN_DONE = 5   # After writing back both (or 1 if !has_sph), lock in; back to pattern_none.

        spl_active_reg = None
        sph_active_reg = None
        possible_offset = 0
        io_sub_seq_state = IO_SUB_PATTERN_NONE  # Not currently in this pattern.

        while virt_pc < (fn_start_pc + fn_size) and virt_pc < pc:
            width = default_fetch_width
            op = int.from_bytes(fn_body[virt_pc - fn_start_pc: virt_pc - fn_start_pc + width],
                                "little", signed=False)
            # print(f'vpc {virt_pc:04x} (w={width}) -- op {op:02x} {op:016b}')

            is_prologue = False  # Don't yet know if this instruction is part of the prologue

            for opcode_rec in prologue_opcodes:
                loop_op = op
                loop_width = width

                if opcode_rec['width'] != default_fetch_width:
                    # Try to decode more than the standard fetch width at once.
                    loop_width = opcode_rec['width']
                    loop_op = int.from_bytes(
                        fn_body[virt_pc - fn_start_pc: virt_pc - fn_start_pc + loop_width],
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
                        spl_active_reg = rd  # We've loaded $SPL into Rd.
                        possible_offset = 0  # Reset possible_offset since we can't have SBIW'd yet.
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
                        sph_active_reg = rd  # We've loaded $SPH into Rd.
                        possible_offset = 0  # Reset possible_offset since we can't have SBIW'd yet.
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
                            io_sub_seq_state += 1  # Wrote back to $SPL
                        elif has_sph and port == sph_port and rd == sph_active_reg:
                            io_sub_seq_state += 1

                        if io_sub_seq_state == IO_SUB_PATTERN_OUT_1 and not has_sph:
                            io_sub_seq_state += 1  # Advance to _DONE; no $SPH to write.

                        if io_sub_seq_state == IO_SUB_PATTERN_DONE:
                            # We have completed the pattern
                            debugger.verboseprint(f"Direct SP adjustment of {possible_offset}")
                            depth += possible_offset  # possible_offset confirmed as frame ptr offset

                            # Reset state machine.
                            io_sub_seq_state = IO_SUB_PATTERN_NONE
                            possible_offset = 0
                            spl_active_reg = None
                            sph_active_reg = None

                virt_pc += loop_width  # Advance virtual $PC past this instruction
                break  # Break out of cycle of decode attempts for this instruction.

            if not is_prologue:
                # We tested all possible prologue opcodes and this instruction isn't one of 'em.
                # We've ran past the end of the prologue and established the frame size.
                break

        debugger.verboseprint(f"Established frame_size={depth}")
        return depth


### AVR-specific opcode decoder functions ###
### (Used in prologue analyzer method.)


def __io_addr_reg(op):
    """
    Return the i/o port address 'A' and register Rr/Rd from a 2-byte IN or OUT opcode sequence
    """
    AVR_IO_IN_ADDR_MASK = 0x060F  # mask for 'A' address for opcode `IN Rd,A`. nb non-contiguous
    addr_part = op & AVR_IO_IN_ADDR_MASK
    addr = ((addr_part >> 5) & 0x0030) | (addr_part & 0x0F)

    AVR_IO_IN_REG_MASK = 0x01F0
    reg_part = op & AVR_IO_IN_REG_MASK
    reg = (reg_part >> 4) & 0x01F
    return (addr, reg)


def __sbiw_rd_i(op):
    """
    Decode and return the 'Rd' and 'immediate' arguments of a SBIW opcode
    """
    AVR_SBIW_RD_MASK = 0x0030
    AVR_SBIW_CONST_MASK = 0x00CF

    imm_part = op & AVR_SBIW_CONST_MASK
    imm = ((imm_part >> 2) & 0x30) | (imm_part & 0xF)

    # rd_part is 2 bits and indicates r24, 26, 28, or 30
    rd_part = (op & AVR_SBIW_RD_MASK) >> 4
    rd = (2 * rd_part) + 24

    return (rd, imm)


def __subi_rd_i(op):
    """
    Return Rd and immediate parts from a SUBI opcode.
    """
    AVR_SUBI_RD_MASK = 0x00F0
    AVR_SUBI_CONST_MASK = 0x0F0F

    imm_part = op & AVR_SUBI_CONST_MASK
    imm = ((imm_part >> 4) & 0xF0) | (imm_part & 0xF)

    # rd_part is 4 bits and indicates 16 <= Rd <= 31
    rd_part = (op & AVR_SUBI_RD_MASK) >> 4
    rd = 16 + rd_part

    return (rd, imm)


# Helper function to assemble opcode decoder record
def __mk_opcode_rec(name, opcode, mask=0xFFFF, width=2, decoder=None):
    return {
        'name':     name,
        'OPCODE':   opcode,
        'MASK':     mask,
        'width':    width,
        'decoder':  decoder,
        }


# Opcodes that can occur within prologue
prologue_opcodes = [
    __mk_opcode_rec('push', 0x920F, 0xFE0F),
    __mk_opcode_rec('pop',  0x900F, 0xFE0F),
    __mk_opcode_rec('nop',  0x0),
    __mk_opcode_rec('eor',  0x2400, 0xFC00),
    __mk_opcode_rec('in',   0xB000, 0xF800, 2, __io_addr_reg),
    __mk_opcode_rec('out',  0xB800, 0xF800, 2, __io_addr_reg),
    __mk_opcode_rec('cli',  0x94F8),
    __mk_opcode_rec('sei',  0x9478),
    __mk_opcode_rec('sbiw', 0x9700, 0xFF00, 2, __sbiw_rd_i),
    __mk_opcode_rec('subi', 0x5000, 0xF000, 2, __subi_rd_i),
    ]

