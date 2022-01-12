# (c) Copyright 2022 Aaron Kimball
#
# Stack machine to evaluate location info from DWARF DW_AT_location bytecode

import elftools.dwarf.dwarf_expr as dwarf_expr

class DwarfExprMachine(object):
    """
    Stack machine to evaluate a DWARF expression to a location address.

    Usage:
        dem = DwarfExprMachine([opcodes], {regs}, debugger)
        addr = dem.eval()

    Depending on the operations performed, 'addr' may have 1 of three types:
        int    - A memory address you should access to get the variable's value.
        str    - The name of a machine register holding the variable's value directly.
        fn     - A function that will access the variable in question when called.
                 Used to assemble results of PIECE operations.

    Or instead of `dem.eval()`, use `dem.access(size)` to access size bytes at addr.

    # TODO(aaron): Handle PIECE, FBREG
    """

    # Dispatch table from opcode to method.
    __dispatch = None

    # Architecture-specific properties

    __instruction_set = None
    __register_mapping = None  # DWARF reg nums -> machine register names
    __addr_size = None         # Architecture's address size in bytes
    __word_len  = None         # Architecture's word size in a register, or as pushed to stack.

    def __init__(self, opcodes, regs, debugger, initial_stack=None):
        # Handle one-time setups for evaluation environment, if needed.
        if DwarfExprMachine.__dispatch == None:
            DwarfExprMachine.__init_dispatch()
        if DwarfExprMachine.__instruction_set == None:
            # Set this up as a class value; assume arch is constant within debugger prgm lifetime
            DwarfExprMachine.__instruction_set = debugger.get.arch_conf('instruction_set')
            DwarfExprMachine.__register_mapping = debugger.get.arch_conf('stack_unwind_registers')
            DwarfExprMachine.__addr_size = debugger.get.arch_conf('ret_addr_size')
            DwarfExprMachine.__word_len = debugger.get.arch_conf('push_word_len')


        self.opcodes = opcodes           # Set of parsed DWARF expression opcodes to evaluate
        self.regs = regs                 # Registers for current stack frame.
        self._debugger = debugger        # Debugger with access to running process SRAM
        self.stack = initial_stack or [] # Initial stack machine state.

    def eval(self):
        """
        Evaluate the bytecode program to resolve the location.
        """
        for op in self.opcodes:
            self._debugger.verboseprint(f'Processing opcode {op.op_name}')
            func = cls.__dispatch[op.op]
            func(self, op)

        return self.top()

    def access(self, size):
        """
        Evaluate the bytecode program to resolve the location. Then get the result at that location.
        """
        addr = self.eval()
        if isinstance(addr, int):
            return self.mem(addr, size)
        elif isinstance(addr, str):
            return self.regs[reg]
        elif callable(addr):
            return addr()
        else
            raise Exception(f"Unknown how to dereference {addr.__class__}: {repr(addr)}")


    def _unimplemented_op(self, op):
        raise Exception(f"Unimplemented DWARF expr op='{op.op_name}' args={op.args}")

    def _addr(self, op):
        self.push(op.args[0]) # Push address argument

    def _const(self, op):
        self.push(op.args[0]) # Push constant argument

    def _deref(self, op):
        addr = self.pop()
        self.push(self.mem(addr, DwarfExprMachine.__addr_size))

    def _xderef(self, op):
        size = op.args[0]
        addr = self.pop()
        self.push(self.mem(addr, size))

    def _dup(self, op):
        self.push(self.top())

    def _drop(self, op):
        self.pop()

    def _over(self, op):
        self.push(self.at_stack(1)

    def _pick(self, op):
        self.push(self.at_stack(op.args[0]))

    def _swap(self, op):
        fst = self.pop()
        snd = self.pop()
        self.push(fst)
        self.push(snd)

    def _rot(self, op):
        fst = self.pop()
        snd = self.pop()
        trd = self.pop()

        self.push(fst)
        self.push(trd)
        self.push(snd)
        
    def _abs(self, op):
        self.push(abs(self.pop()))

    def _and(self, op):
        fst = self.pop()
        snd = self.pop()
        self.push(fst & snd)
        
    def _div(self, op):
        fst = self.pop()
        snd = self.pop()
        self.push(snd / fst)
        
    def _minus(self, op):
        fst = self.pop()
        snd = self.pop()
        self.push(snd - fst)

    def _mod(self, op):
        fst = self.pop()
        snd = self.pop()
        self.push(snd % fst)

    def _mul(self, op):
        fst = self.pop()
        snd = self.pop()
        self.push(snd * fst)

    def _neg(self, op):
        self.push(-self.pop())

    def _not(self, op):
        self.push(~self.pop())

    def _or(self, op):
        fst = self.pop()
        snd = self.pop()
        self.push(snd | fst)

    def _plus(self, op):
        fst = self.pop()
        snd = self.pop()
        self.push(snd + fst)

    def _plus_uconst(self, op):
        base = self.pop()
        const = op.args[0]
        self.push(base + const)

    def _shl(self, op):
        fst = self.pop()
        snd = self.pop()
        self.push(snd << fst)
        
    def _shr(self, op):
        fst = self.pop()
        snd = self.pop()

        # For logical right shift, 'cast' the snd argument to unsigned
        # see https://realpython.com/python-bitwise-operators/#arithmetic-vs-logical-shift
        unsigned_snd = snd % (1 << (DwarfMachineExpr.__addr_size * 8))
        self.push(unsigned_snd >> fst)

    def _shra(self, op):
        fst = self.pop()
        snd = self.pop()
        self.push(snd >> fst) # Arithmetic right shift.

    def _xor(self, op):
        fst = self.pop()
        snd = self.pop()
        self.push(snd ^ fst)

    def _eq(self, op):
        fst = self.pop()
        snd = self.pop()
        self.push(1 * (snd == fst))

    def _ge(self, op):
        fst = self.pop()
        snd = self.pop()
        self.push(1 * (snd >= fst))

    def _gt(self, op):
        fst = self.pop()
        snd = self.pop()
        self.push(1 * (snd > fst))

    def _le(self, op):
        fst = self.pop()
        snd = self.pop()
        self.push(1 * (snd <= fst))

    def _lt(self, op):
        fst = self.pop()
        snd = self.pop()
        self.push(1 * (snd < fst))

    def _ne(self, op):
        fst = self.pop()
        snd = self.pop()
        self.push(1 * (snd != fst))

    # We've lost size information about opcodes, so we cannot SKIP or BRA
    # for control flow.
    _skip = _unimplemented_op
    _bra = _unimplemented_op

    def _piece(self, op):
        # TODO(aaron): Implement PIECE
        # This should actually create a closure that assembles the result and push
        # that to the stack.
        _unimplemented_op(op)

    def _nop(self, op):
        pass

    def _literal(self, op):
        """ lit0 .. lit31 op - Push the literal constant value 0...31 """
        val = op.op - dwarf_expr.DW_OP_name2opcode['DW_OP_lit0']
        self.push(val)

    def _reg_direct(self, op):
        """ reg0 .. reg31 op - look up data directly from the register. """
        # register id encoded in opcode itself.
        reg_num = op.op - dwarf_expr.DW_OP_name2opcode['DW_OP_reg0']
        self.push(self.reg_name(reg_num))

    def _regx(self, op):
        """ value is directly in register arg[0] """ 
        reg_num = op.args[0]
        self.push(self.reg_name(reg_num))

    def _reg_lookup(self, op):
        """ breg0 .. breg31 op - look up data at the address stored in the register. """
        reg_num = op.op - dwarf_expr.DW_OP_name2opcode['DW_OP_reg0']
        self._reg_lookup_internal(reg_num)

    def _bregx(self, op):
        """ lookup data at addr in register arg[0] + offset arg[1] """
        reg_num = op.args[0]
        offset = op.args[1]
        self._reg_lookup_internal(reg_num, offset)

    def _reg_lookup_internal(self, reg_num, offset=0):
        """ handle breg0...breg31 and bregx after args are decoded. """
        addr = self.reg(reg_num)
        if DwarfExprMachine.__instruction_set == 'avr' and  0 <= reg_num and reg_num <= 31:
            # Addresses are 2-bytes wide but registers r0..r31 are 1 byte. (r32=SP is 2 bytes.)
            # Assume it's a register like X, Y, or Z and use two successive regs.
            addr_hi = self.reg(reg_num + 1)
            addr = ((addr_hi & 0xFF) << 8) | (addr & 0xFF)
        addr += offset
        self.push(addr)

    def _fbreg(self, op):
        # TODO(aaron): Implement FBREG
        _unimplemented_op(op)


    # Unimplemented opcodes; not specified in DWARF2; maybe D3 or D4?
    _deref_size = _unimplemented_op
    _xderef_size = _unimplemented_op
    _push_object_address = _unimplemented_op
    _call2 = _unimplemented_op
    _call4 = _unimplemented_op
    _call_ref = _unimplemented_op
    _form_tls_address = _unimplemented_op
    _call_frame_cfa = _unimplemented_op
    _bit_piece = _unimplemented_op
    _implicit_value = _unimplemented_op
    _stack_value = _unimplemented_op
    _implicit_pointer = _unimplemented_op
    _addrx = _unimplemented_op
    _constx = _unimplemented_op
    _entry_value = _unimplemented_op
    _const_type = _unimplemented_op
    _regval_type = _unimplemented_op
    _deref_type = _unimplemented_op
    _xderef_type = _unimplemented_op
    _convert = _unimplemented_op
    _reinterpret = _unimplemented_op
    _push_tls_address = _unimplemented_op
    _implicit_pointer = _unimplemented_op
    _entry_value = _unimplemented_op
    _const_type = _unimplemented_op
    _regval_type = _unimplemented_op
    _deref_type = _unimplemented_op
    _convert = _unimplemented_op
    _parameter_ref = _unimplemented_op

    ### Stack operations ###

    def top(self):
        """ return top item on the stack. """
        if not len(self.stack):
            return None

        return self.stack[-1]

    def at_stack(self, n):
        """ return item at position 'n'. 0 is the top of the stack, 1 is just below that, etc. """
        k = -(n + 1)
        return self.stack[k]

    def pop(self):
        """ pop top item from stack. """
        return self.stack.pop()

    def push(self, v):
        self.stack.append(v)

    ### Debugger interaction ###

    def reg(self, reg_num):
        """
        Get the value contained within a given register.
        @param reg_num the numeric register id as DWARF understands the registers.
            This must be converted by arch_conf('stack_unwind_registers') to a real
            register name before looking up in the regs map.
        @return the value of the register
        """
        return self.regs[DwarfExprMachine.__register_mapping[reg_num]]

    def reg_name(self, reg_num):
        """
        Get the name of a machine register associated with the DWARF register number argument.
        """
        return DwarfExprMachine.__register_mapping[reg_num]

    def mem(self, addr, size=1):
        """
        Get the value contained in SRAM at the specified address.
        """
        return self._debugger.get_sram(addr, size)

    ### Setup ###

    @classmethod
    def __init_dispatch(cls):
        """
        Initialize the opcode dispatch table the first time we're used.
        """
        d = {
            0x03: _addr, # DW_OP_addr
            0x06: _deref, # DW_OP_deref
            0x08: _const, # DW_OP_const1u
            0x09: _const, # DW_OP_const1s
            0x0a: _const, # DW_OP_const2u
            0x0b: _const, # DW_OP_const2s
            0x0c: _const, # DW_OP_const4u
            0x0d: _const, # DW_OP_const4s
            0x0e: _const, # DW_OP_const8u
            0x0f: _const, # DW_OP_const8s
            0x10: _const, # DW_OP_constu
            0x11: _const, # DW_OP_consts
            0x12: _dup, # DW_OP_dup
            0x13: _drop, # DW_OP_drop
            0x14: _over, # DW_OP_over
            0x15: _pick, # DW_OP_pick
            0x16: _swap, # DW_OP_swap
            0x17: _rot, # DW_OP_rot
            0x18: _xderef, # DW_OP_xderef
            0x19: _abs, # DW_OP_abs
            0x1a: _and, # DW_OP_and
            0x1b: _div, # DW_OP_div
            0x1c: _minus, # DW_OP_minus
            0x1d: _mod, # DW_OP_mod
            0x1e: _mul, # DW_OP_mul
            0x1f: _neg, # DW_OP_neg
            0x20: _not, # DW_OP_not
            0x21: _or, # DW_OP_or
            0x22: _plus, # DW_OP_plus
            0x23: _plus_uconst, # DW_OP_plus_uconst
            0x24: _shl, # DW_OP_shl
            0x25: _shr, # DW_OP_shr
            0x26: _shra, # DW_OP_shra
            0x27: _xor, # DW_OP_xor
            0x28: _bra, # DW_OP_bra
            0x29: _eq, # DW_OP_eq
            0x2a: _ge, # DW_OP_ge
            0x2b: _gt, # DW_OP_gt
            0x2c: _le, # DW_OP_le
            0x2d: _lt, # DW_OP_lt
            0x2e: _ne, # DW_OP_ne
            0x2f: _skip, # DW_OP_skip
            0x90: _regx, # DW_OP_regx
            0x91: _fbreg, # DW_OP_fbreg
            0x92: _bregx, # DW_OP_bregx
            0x93: _piece, # DW_OP_piece
            0x94: _deref_size, # DW_OP_deref_size
            0x95: _xderef_size, # DW_OP_xderef_size
            0x96: _nop, # DW_OP_nop
            0x97: _push_object_address, # DW_OP_push_object_address
            0x98: _call2, # DW_OP_call2
            0x99: _call4, # DW_OP_call4
            0x9a: _call_ref, # DW_OP_call_ref
            0x9b: _form_tls_address, # DW_OP_form_tls_address
            0x9c: _call_frame_cfa, # DW_OP_call_frame_cfa
            0x9d: _bit_piece, # DW_OP_bit_piece
            0x9e: _implicit_value, # DW_OP_implicit_value
            0x9f: _stack_value, # DW_OP_stack_value
            0xa0: _implicit_pointer, # DW_OP_implicit_pointer
            0xa1: _addrx, # DW_OP_addrx
            0xa2: _constx, # DW_OP_constx
            0xa3: _entry_value, # DW_OP_entry_value
            0xa4: _const_type, # DW_OP_const_type
            0xa5: _regval_type, # DW_OP_regval_type
            0xa6: _deref_type, # DW_OP_deref_type
            0xa7: _xderef_type, # DW_OP_xderef_type
            0xa8: _convert, # DW_OP_convert
            0xa9: _reinterpret, # DW_OP_reinterpret
            0xf2: _GNU_implicit_pointer, # DW_OP_GNU_implicit_pointer
            0xf3: _GNU_entry_value, # DW_OP_GNU_entry_value
            0xf4: _GNU_const_type, # DW_OP_GNU_const_type
            0xf5: _GNU_regval_type, # DW_OP_GNU_regval_type
            0xf6: _GNU_deref_type, # DW_OP_GNU_deref_type
            0xf7: _GNU_convert, # DW_OP_GNU_convert
            0xfa: _GNU_parameter_ref, # DW_OP_GNU_parameter_ref
        }

        # Add lit0..lit31, reg0..reg31, breg0..breg31 to mappings
        for i in range(0, 32):
            d[i + 0x30] = _literal
            d[i + 0x50] = _reg_direct
            d[i + 0x70] = _reg_lookup

        # Convert the map above into an array for fast lookups.
        cls.__dispatch = (max(d.keys()) + 1) * [ _unimplemented_op ]
        for (idx, func) in d.items():
            cls.__dispatch[idx] = func

    @classmethod
    def hard_reset_state(cls):
        """
        Flush class-level initializations and require refresh for next use.
        """
        cls.__dispatch = None
        cls.__instruction_set = None
        cls.__register_mapping = None
        cls.__word_len = None
        cls.__addr_size = None

