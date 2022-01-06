# (C) Copyright 2021 Aaron Kimball
#
# Stack analysis routines.


_debugger_methods = [
  "__vector_17",     # timer interrupt
  "__dbg_service",   # The debugger interactive service loop
  ".*__dbg_break.*", # The overloaded __dbg_break() methods
]



def stack_frame_size_for_method(debugger, pc, method_name):
    """
        Given a program counter (PC) somewhere within the body of `method_name`, determine
        the size of the current stack frame at that point and return it.

        i.e., if SP is 'x' and this method returns 4, then 4 bytes of stack RAM have been
        filled by the method (x+1..x+4) and the (2 byte AVR) return address is at
        x+5..x+6.
    """

    # Pull opcode details from architecture configuration.
    push_op       = debugger.get_arch_conf("PUSH_OPCODE")
    push_op_mask  = debugger.get_arch_conf("PUSH_OP_MASK")
    push_op_width = debugger.get_arch_conf("push_op_width")

    pop_op       = debugger.get_arch_conf("POP_OPCODE")
    pop_op_mask  = debugger.get_arch_conf("POP_OP_MASK")
    pop_op_width = debugger.get_arch_conf("pop_op_width")

    push_word_len = debugger.get_arch_conf("push_word_len") # nr of bytes a PUSH adds to the stack.

    prologue_opcodes   = debugger.get_arch_conf("PROLOGUE_OPCODES")
    prologue_op_masks  = debugger.get_arch_conf("PROLOGUE_OPCODE_MASKS")
    prologue_op_widths = debugger.get_arch_conf("prologue_opcode_widths")

    default_fetch_width = debugger.get_arch_conf("default_op_width") # standard instruction decode size

    fn_body = debugger.image_for_symbol(method_name)
    fn_sym = debugger.lookup_sym(method_name)
    if fn_sym is None:
        print(f"No function symbol for method: {method_name}")
        return None

    fn_start_pc = fn_sym['addr']
    fn_size = fn_sym['size']

    default_fetch_width = max(default_fetch_width, push_op_width, pop_op_width)

    print(f"Getting frame size for method {method_name} (@PC {pc:04x})")
    print(f"start addr {fn_start_pc:04x}, size {fn_size} bytes")
    #print(f"Function body:\n{fn_body}")

    depth = 0
    virt_pc = fn_start_pc
    # Walk through the instructions of the method until we reach the end of the prologue
    # or the current PC. Track the stack size through this point. We believe we are done
    # with the prologue when we encounter an instruction that is not a PUSH, POP, or a
    # member of the PROLOGUE_OPCODES list.
    #
    # TODO(aaron): This will not properly backtrace if the method performs PUSH operations
    # after the method prologue. Without knowledge of the basic block / control flow structure
    # within the method (or the path withn those taken by the PC from prologue to its current point)
    # we can't just safely read linearly. If we do need to debug methods with this kind of
    # operation, we need to be able to rely on an explicit frame pointer.
    while virt_pc < (fn_start_pc + fn_size) and virt_pc < pc:
        width = default_fetch_width
        op = int.from_bytes(fn_body[virt_pc - fn_start_pc : virt_pc - fn_start_pc + width], 
            "little", signed=False)
        #print(f'vpc {virt_pc:04x} (w={width}) -- op {op:02x} {op:016b}')

        if (op & pop_op_mask) == pop_op:
            # it's a pop
            depth -= push_word_len
        elif (op & push_op_mask) == push_op:
            # it's a push
            depth += push_word_len
        else:
            is_prologue = False
            for i in range(0, len(prologue_opcodes)):
                this_op = op
                width = default_fetch_width

                if prologue_op_widths[i] != default_fetch_width:
                    width = prologue_op_widths[i]
                    this_op = int.from_bytes(fn_body[virt_pc - fn_start_pc : virt_pc - fn_start_pc + width], 
                        "little", signed=False)

                if (this_op & prologue_op_masks[i]) == prologue_opcodes[i]:
                    is_prologue = True # non-stack-modifying prologue opcode confirmed
                    break

            if not is_prologue:
                # Hit some other opcode in the main body before we reached the current PC.
                # Stack frame size established.
                break

        virt_pc += width

    print(f"Got final depth {depth}")
    return depth


def stack_frame_size_by_pc(debugger, pc):
    """
        Given a program counter (PC), determine what method we're in and return the size
        of the stack frame
    """
    method_name = debugger.function_sym_by_pc(pc)
    return stack_frame_size_for_method(debugger, pc, method_name)


