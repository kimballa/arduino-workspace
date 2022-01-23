# (c) Copyright 2022 Aaron Kimball
#
# Stack machine to evaluate location info from DWARF DW_AT_location bytecode

import elftools.dwarf.dwarf_expr as dwarf_expr

import arduino_dbg.debugger as dbg
import arduino_dbg.types as types

class ExprFlags(object):
    """
    Flags that provide info about the result returned by eval() or access().
    """

    # Top level messages.
    OK                      =     0x1     # Successfully produced a value.
    WARNED                  =     0x2     # Produced a value but with warnings.

    # Error codes
    ERR_NO_LOCATION         =    0x10     # No location data available.
    ERR_PC_OUT_OF_BOUNDS    =    0x20     # Location data available but PC is not in a range
                                          # where the location expr for this var is valid;
                                          # var is out of scope.

    # Warning codes (set WARNED in addition to one or more of these)
    WARN_CLOBBERED_REG      =   0x100     # Warning: in addition to stack-unwinding, we rely
                                          # on the value of a caller-save register which may
                                          # be clobbered by the time we read the value.

    # Information about how the location was calculated.
    MULTIPART               =  0x1000     # The address is in multiple pieces
    REGISTER_UNWIND         =  0x2000     # The result relies on processing the .debug_frame
                                          # stack unwinding info
    COMPILE_TIME_CONST      =  0x4000     # Value was embedded directly into the .debug_info
                                          # as a compiler-deduced constant.
    CONST_ADDR              =  0x8000     # Address provided by DW_OP_addr or addrx
    FLASH_ADDR              = 0x10000     # Address retrieved from flash segment, not RAM.


    ERRORS_MASK             =    0xF0     # Errors fit under this mask
    WARNINGS_MASK           =   0xF02     # Warnings fit under this mask

    @staticmethod
    def successful(flags):
        """
        Return True for any successful (fully-clean or with-warnings) response.
        """
        return flags & ExprFlags.OK

    @staticmethod
    def has_warnings(flags):
        """
        Return True if the warning bit is set.
        """
        return (flags & ExprFlags.WARNINGS_MASK) != 0

    @staticmethod
    def has_errors(flags):
        """
        Return True if any errors are noticed.
        """
        return (flags & ExprFlags.ERRORS_MASK) != 0

    @staticmethod
    def get_message(flags):
        """
        Return a formatted user-friendly message about errors or warnings encountered.
        """
        messages = ''
        if ExprFlags.has_errors(flags):
            if flags & ExprFlags.ERR_NO_LOCATION:
                messages = '(No location data)'
            elif flags  & ExprFlags.ERR_PC_OUT_OF_BOUNDS:
                messages = '(Out of scope)'
        elif ExprFlags.has_warnings(flags):
            if flags & ExprFlags.WARN_CLOBBERED_REG:
                messages = '(Warning: relies on call-clobbered register; data uncertain)'

        if flags & ExprFlags.FLASH_ADDR:
            if len(messages):
                messages += ' '
            messages += '(Flash data)'
        return messages


class DWARFExprMachine(object):
    """
    Stack machine to evaluate a DWARF expression to a location address.

    Usage:
        dem = DWARFExprMachine([opcodes], {regs}, debugger)
        addrs = dem.eval()

    addrs is a list of (addr, size) tuples. If the value is in multiple reigsters or
    addresses, this instructs how many bytes to fetch from each such addr. If the
    result is in a single contiguous location, size=DWARFExprMachine.ALL.

    Depending on the operations performed, 'addr' may have different types:
        int    - A memory address you should access to get the variable's value.
        str    - The name of a machine register holding the variable's value directly.

    Or instead of `dem.eval()`, use `dem.access(val_type)` to directly retrieve a result with the
    specified data type from the location identified by the expression. Instead of val_type, you
    can also pass `size=n` to grab a value exactly n bytes wide.

    After calling eval() once, you must call `dem.reset()` to run again. The reset
    method gives the opportunity to refresh the current register state, regs + instructions,
    or regs + instructions + initial stack.
    """

    # Dispatch table from opcode to method.
    __dispatch = None

    # Architecture-specific properties

    __instruction_set = None
    __register_mapping = None  # DWARF reg nums -> machine register names
    __addr_size = None         # Architecture's address size in bytes
    __word_len  = None         # Architecture's word size in a register, or as pushed to stack.

    ALL = -1                # 'size' for degenerate 'piece' instruction to get the entire result.
    TOP = '__dw_stack_top'  # 'register' for access() method to use to grab from top-of-stack.

    def __init__(self, opcodes, regs, debugger, initial_stack=None):
        # Handle one-time setups for evaluation environment, if needed.
        if DWARFExprMachine.__dispatch == None:
            DWARFExprMachine.__init_dispatch()
        if DWARFExprMachine.__instruction_set == None:
            # Set this up as a class value; assume arch is constant within debugger prgm lifetime
            DWARFExprMachine.__instruction_set = debugger.get_arch_conf('instruction_set')
            DWARFExprMachine.__register_mapping = debugger.get_arch_conf('stack_unwind_registers')
            DWARFExprMachine.__addr_size = debugger.get_arch_conf('ret_addr_size')
            DWARFExprMachine.__word_len = debugger.get_arch_conf('push_word_len')


        self.opcodes = opcodes           # Set of parsed DWARF expression opcodes to evaluate
        self.regs = regs                 # Registers for current stack frame.
        self._debugger = debugger        # Debugger with access to running process SRAM
        self.stack = initial_stack or [] # Initial stack machine state.
        self._pieces = []
        self._scope = None               # Containing scope (used for frame base calc)
        self._frame = None               # Backtrace frame for current scope's dynamic state.
        self._flags = 0                  # Flags built up during response evaluation.

    def setScope(self, scope):
        self._scope = scope

    def setFrame(self, frame):
        self._frame = frame

    def eval(self):
        """
        Evaluate the bytecode program to resolve the location.

        Returns a list of addresses and piece-widths where the data is held, and an int
        of bitflags (from ExprFlags) describing the location-resolution process.

        If there is a single output address, the piece-width is DWARFExprMachine.ALL.
        Addresses may be either integer memory addresses or strings indicating registers to
        inspect.
        """
        self._flags = 0
        self._pieces = []
        for op in self.opcodes:
            self._debugger.verboseprint('Processing opcode ', op.op_name, '; args=', op.args)
            func = DWARFExprMachine.__dispatch[op.op]
            func(self, op)

        # What's the result address? If we got PIECE instructions, deliver a list of addrs and
        # sizes. Otherwise, return a singleton list with the address and DEM.ALL..
        self._flags |= ExprFlags.OK
        if len(self._pieces):
            self._debugger.verboseprint(f'Resolved to set of pieces: {self._pieces}')
            if len(self._pieces) > 1:
                self._flags |= ExprFlags.MULTIPART
            return self._pieces, self._flags
        else:
            out = self.top()
            if isinstance(out, str):
                self._debugger.verboseprint('Resolved address: register ', out)
            else:
                self._debugger.verboseprint('Resolved address: 0x', dbg.VHEX4, out)
            return [(out, DWARFExprMachine.ALL)], self._flags

    @staticmethod
    def __make_list_for_addr(addr):
        """
        Return an address list and flag set for a known memory address.
        """
        return [(addr, DWARFExprMachine.ALL)], ExprFlags.OK

    def __access_big_endian(self, addrs, flags, size, offset=0):
        """
        Access a scalar word of the specified size in big-endian format. Subcomponents of the word
        are located by 1 or more addresses in 'addrs'.

        @param addrs can be a singleton (addr, DWARFExprMachine.ALL) tuple list, or a list of
            addresses and registers with sub-scalar sizes.
        @param flags specifies the process by which the addrs list was calculated.
        @param size is the total result word size to fetch from this address.
        @param offset if non-zero treats 'addrs' as a base address for an array and the result word
            is retrieved from *(addrs + offset)
        """
        out = 0 # scalar result
        for (addr, piece_size) in addrs:
            if piece_size == DWARFExprMachine.ALL:
                piece_size = size # There is only one piece, and it is the caller-decl'd size
            elif offset != 0:
                raise Exception("Cannot access array with addr in multiple pieces")

            if isinstance(addr, int):
                out = (out << (8 * piece_size)) | self.mem(addr + offset, piece_size)
            elif isinstance(addr, str):
                if offset != 0:
                    raise Exception("Cannot access array with non-memory address")
                elif addr == DWARFExprMachine.TOP:
                    regval = self.top()
                else:
                    regval = self.regs[addr]

                if piece_size == 1:
                    regval = regval & 0xFF
                elif piece_size == 2:
                    regval = regval & 0xFFFF
                elif piece_size == 4:
                    regval = regval & 0xFFFFFFFF
                elif piece_size == 8:
                    regval = regval & 0xFFFFFFFFFFFFFFFF
                else:
                    raise Exception(f'Unknown piece size arg {piece_size}')
                out = (out << (8 * piece_size)) | regval
            else:
                raise Exception(f"Unknown how to dereference {addr.__class__}: {repr(addr)}")

        return out, flags

    def __access_little_endian(self, addrs, flags, size, offset=0):
        """
        Access a scalar word of the specified size in little-endian format. Subcomponents of the word
        are located by 1 or more addresses in 'addrs'.

        @param addrs can be a singleton (addr, DWARFExprMachine.ALL) tuple list, or a list of
            addresses and registers with sub-scalar sizes.
        @param flags specifies the process by which the addrs list was calculated.
        @param size is the total result word size to fetch from this address.
        @param offset if non-zero treats 'addrs' as a base address for an array and the result word
            is retrieved from *(addrs + offset)
        """
        # Check const addr flag to see if we should be segment-aware in our data retrieval.
        const_addr = flags & ExprFlags.CONST_ADDR
        arch = self._debugger.get_arch_conf('instruction_set')

        out = 0 # for scalar result
        new_shift = 0
        existing_mask = 0
        for (addr, piece_size) in addrs:
            mem_fn = self.mem
            if const_addr and arch == "avr":
                # We got a flat-address-space addr directly from compiler output.
                # Translate that into the AVR segment-aware memory space and
                # choose the correct address to read and segment accessor function.
                # (nb this check is not needed in __access_big_endian since AVR is
                # little endian-only.)

                data_seg_mask = self._debugger.get_arch_conf("DATA_ADDR_MASK")
                if isinstance(addr, int) and addr == addr & data_seg_mask:
                    # It's a constant address and it's not in .data (i.e., it's in .text).
                    mem_fn = self.flash # Use self.flash() to load from .text
                    flags |= ExprFlags.FLASH_ADDR
                elif isinstance(addr, int) and addr != addr & data_seg_mask:
                    addr = addr & data_seg_mask # remove 0x800000 .data prefix from addr.

            if piece_size == DWARFExprMachine.ALL:
                piece_size = size # There is only one piece, and it is the caller-decl'd size
            elif offset != 0:
                raise Exception("Cannot access array with addr in multiple pieces")

            if isinstance(addr, int):
                out = (mem_fn(addr + offset, piece_size) << new_shift) | \
                    (out & existing_mask)
            elif isinstance(addr, str):
                if offset != 0:
                    raise Exception("Cannot access array with non-memory address")
                elif addr == DWARFExprMachine.TOP:
                    regval = self.top()
                else:
                    regval = self.regs[addr]
                out = (regval << new_shift) | (out & existing_mask)
            else:
                raise Exception(f"Unknown how to dereference {addr.__class__}: {repr(addr)}")

            # Account for bit width of result built-so-far growing by piece_size bytes.
            for i in range(0, piece_size):
                # mask off `piece_size` more bytes on lsb-side of result as present.
                existing_mask <<= 8
                existing_mask |= 0xFF

            new_shift += 8 * piece_size # next new bytes shl by piece_size * 8 more bits
                                        # before slotting in

        out &= existing_mask # Ensure we don't return data that's too wide for size.
        return out, flags

    # Maximum length to explore for a null-terminated string.
    MAX_NULL_TERM_STRING_LEN = 64

    def __access_resolved_address(self, addrs, flags=0, typ=None, size=None):
        """
        Given an address list 'addrs' of the form returned by 'DWARFExprMachine.eval()', and
        associated flags, as well as datatype and/or size of data to retrieve, access the
        information in memory and return it in the appropriate host datatype/format.

        Returns the value of size 'size' located at the address computed by the expression and
        the flags associated with identifying its location.

        The return value may be an integer, a list, or a string depending on the data type
        input. If the value is a pointer, the result is a tuple of (address, pointed-to-value).
        Multiple layers of indirection can return values nested like a LISP-style list:
        (car, (cadr, cddr...)).
        """
        access_size = None
        access_count = 1
        if size is not None:
            # Fetch exactly as many bytes as requested.
            access_size = size
            if typ and typ.size != size:
                self._debugger.verboseprint('Warning: both type and size specified in access(); ',
                    'size=', size, ' but type width is ', typ.size, '. ',
                    'Using explicit size=', size, '.')
        elif typ and typ.is_array():
            access_count = typ.get_array_len()
            access_size = typ.get_array_elem_size()
        elif typ:
            access_size = typ.size
        else:
            # Didn't get enough parameters to know what type to fetch?
            access_size = self._debugger.get_arch_conf('push_word_len')
            self._debugger.verboseprint(
                'Warning: No type or size specified to DWARFExprMachine.access(); ',
                'defaulting to CPU word size of ', access_size)

        if self._debugger.get_arch_conf("endian") == "big":
            access_fn = self.__access_big_endian
        else:
            access_fn = self.__access_little_endian

        outlist=[] # for array-based results
        if access_count == types.VARIABLE_LEN_ARRAY:
            # We're reading a null-termianted string from the specified address. Continue reading
            # until we reach a null terminator.
            assert access_size > 0
            offset = 0
            while True:
                (out, flags) = access_fn(addrs, flags, access_size, offset)
                outlist.append(out)
                if out == 0:
                    break # Found null terminator.
                offset += access_size
                if offset == self.MAX_NULL_TERM_STRING_LEN:
                    # Don't run on in memory forever. Add an ellipse and call it a day.
                    outlist.extend(3 * [ord('.')])
                    break
        else:
            for i in range(0, access_count):
                (out, flags) = access_fn(addrs, flags, access_size, i * access_size)
                outlist.append(out)

        if access_count != 1:
            out = outlist

        if typ.is_string() and isinstance(out, list):
            # Convert output from array to string.
            out_chars = list(map(lambda c: chr(c), out))
            try:
                null_idx = out_chars.index('\x00')
                # Chomp at the first null terminator we see.
                out_chars = out_chars[:null_idx]
            except ValueError:
                pass # No null terminator to chomp.

            out = ''.join(out_chars)
        elif typ.pointer_depth() > 0 and isinstance(out, int) and out != 0:
            # We have a pointer to another value.
            deref_type = typ.get_dereferenced_type()
            if deref_type is not None:
                if deref_type.is_char():
                    # We dereferenced a pointer to a char. Don't just read as a single char;
                    # read all chars until we encounter '\0'.
                    deref_type = types.NullTermString()
                deref_addr = out
                deref_addr_lst, deref_flags = DWARFExprMachine.__make_list_for_addr(deref_addr)
                # Look up what it's dereferencing.
                deref_out, _ = self.__access_resolved_address(deref_addr_lst, deref_flags, deref_type)
                out = (deref_addr, deref_out) # 'out' is the address and its pointee.

        if self._debugger.get_conf('dbg.verbose'):
            if isinstance(out, int):
                self._debugger.verboseprint(f'Resolved value=0x{out} size={access_size}')
            elif isinstance(out, str):
                # It's a string.
                self._debugger.verboseprint(f'Resolved str={repr(out)} len={len(out)}')
            elif isinstance(out, list):
                # It's an array.
                self._debugger.verboseprint(f'Resolved array={list(map(lambda x: f"0x{x:x}", out))} ' +
                    f'elem_size={access_size}, cnt={access_count}')
            else:
                # Unsure what type this is, exactly.
                self._debugger.verboseprint(f'Resolved value: {out} ' +
                    f'(size={access_size}, cnt={access_count})')

        return out, flags

    def access(self, typ=None, size=None):
        """
        Evaluate the bytecode program to resolve the location. Then get the result at that location.
        Returns the value of size 'size' located at the address computed by the expression and
        the flags associated with identifying its location.

        The return value may be an integer, a list, or a string depending on the data type
        input.
        """
        (addrs, flags) = self.eval()
        return self.__access_resolved_address(addrs, flags, typ, size)


    def reset(self, new_regs=None, new_opcodes=None, new_stack=None):
        """
        Resets the expression processor state to enable the objec to perform a new computation.

        If new_regs or new_opcodes are 'None', they are left as-is.
        If new_stack is 'None', the stack is cleared to an empty stack.

        Otherwise, the new non-None values replace the internal state.
        """
        self.flags = 0 # clear flags on reset.

        if new_regs is not None:
            self.regs = new_regs

        if new_opcodes is not None:
            self.opcodes = new_opcodes

        if new_stack is not None:
            self.stack = new_stack
        else:
            # Generally we don't want to retain the old stack under any normal reset condition;
            # we want to have a fresh empty satck. The prior eval() will have left its computed
            # address on the stack and we want to clear that.
            self.stack = []


    def _unimplemented_op(self, op):
        raise Exception(f"Unimplemented DWARF expr op='{op.op_name}' ({op.op:x}) args={op.args}")

    def _addr(self, op):
        self._flags |= ExprFlags.CONST_ADDR # Retrieved from a literal address. Result may thus
                                            # be segment-aware in a segmented memory space.
        self.push(op.args[0]) # Push address argument

    def _const(self, op):
        self.push(op.args[0]) # Push constant argument

    def _deref(self, op):
        addr = self.pop()
        self.push(self.mem(addr, DWARFExprMachine.__addr_size))

    def _xderef(self, op):
        size = op.args[0]
        addr = self.pop()
        self.push(self.mem(addr, size))

    def _dup(self, op):
        self.push(self.top())

    def _drop(self, op):
        self.pop()

    def _over(self, op):
        self.push(self.at_stack(1))

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
        # Mark that the addr on top of the stack is a piece of the result, size N.
        addr = self.top()
        size = op.args[0]
        piece = (addr, size)
        self._pieces.append(piece)

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
        reg_num = op.op - dwarf_expr.DW_OP_name2opcode['DW_OP_breg0']
        self._reg_lookup_internal(reg_num)

    def _bregx(self, op):
        """ lookup data at addr in register arg[0] + offset arg[1] """
        reg_num = op.args[0]
        offset = op.args[1]
        self._reg_lookup_internal(reg_num, offset)

    def _reg_lookup_internal(self, reg_num, offset=0):
        """ handle breg0...breg31 and bregx after args are decoded. """
        addr = self.reg(reg_num)
        if DWARFExprMachine.__instruction_set == 'avr' and  0 <= reg_num and reg_num <= 31:
            # Addresses are 2-bytes wide but registers r0..r31 are 1 byte. (r32=SP is 2 bytes.)
            # Assume it's a register like X, Y, or Z and use two successive regs.
            addr_hi = self.reg(reg_num + 1)
            addr = ((addr_hi & 0xFF) << 8) | (addr & 0xFF)
        addr += offset
        self.push(addr)

    def _fbreg(self, op):
        if self._scope is None:
            raise Exception("Cannot evaluate DW_OP_fbreg without containing scope")

        fb_addr = self._scope.evalFrameBase(self.regs)
        if fb_addr is None:
            # Scope isn't helpful enough.
            raise Exception("Cannot evaluate DW_OP_fbreg; missing/invalid DW_AT_frame_base in scope")

        offset = op.args[0]
        self.push(fb_addr + offset)


    def _stack_value(self, op):
        # DW_OP_stack_value says that the _location_ we are computing does not
        # exist in memory or registers at a particular address, but the _value_ at
        # that logical location is currently at stack.top(). (DWARF v4)

        piece = (DWARFExprMachine.TOP, DWARFExprMachine.ALL)
        self._pieces.append(piece)

    def _entry_value(self, op):
        """
        The op contains a location expr. Push onto the eval stack the value
        held at that location when the current method *began* executing, regardless
        of how far through the method the $PC has already advanced.

        See DWARFv5 sec 2.5.1.7
        """
        self._flags |= ExprFlags.REGISTER_UNWIND
        sub_location = op.args[0] # sub_location is a list of DWARFExprOp's.
        # It's either a single opcode identifying a register (DW_OP_regN)
        # or a full expression computing a more complex location. We evaluate this
        # location in a brand new dwarf expr machine.
        sub_machine = DWARFExprMachine(sub_location, self.regs, self._debugger)
        unwind_location_parts, sub_flags = sub_machine.eval()
        self._flags |= (sub_flags & ~ExprFlags.OK) # Attach all subflags minus the final OK.
        if len(unwind_location_parts) != 1:
            raise Exception(
                f"Cannot unwind ENTRY_LOCATION in multiple parts; got len={len(unwind_location_parts)}")
        if ExprFlags.has_errors(sub_flags):
            raise Exception(
                f"Error getting entry location: {ExprFlags.get_message(sub_flags)}")

        (unwind_location, _) = unwind_location_parts[0]
        if not isinstance(unwind_location, str):
            raise Exception(f"Cannot unwind ENTRY_LOCATION in memory; got addr {unwind_location}")
        elif self._frame is None:
            # We have identified a specific value to grab from the frame's register unwind set but
            # we don't have a backtrace frame to use for unwinding.
            raise Exception(f'Cannot unwind register \'{unwind_location}\'; no backtrace frame set')
        else:
            # We have identified a specific register whose value at method-start we want to extract.
            #  - unwind_location is a string holding an architectural register name.
            #  - self._frame holds a backtrace stack.CallFrame we can use to unwind.
            start_regs = self._frame.unwind_registers(self.regs)
            start_val = start_regs[unwind_location]
            self._debugger.verboseprint(f'Unwinding register {unwind_location} to value 0x{start_val:x}')
            call_clobbers = self._debugger.get_arch_conf("call_clobbered_registers")
            try:
                call_clobbers.index(unwind_location)
                self._flags |= ExprFlags.WARN_CLOBBERED_REG | ExprFlags.WARNED
            except ValueError:
                pass # This is the happy path.
            self.push(start_val)

    def _call_frame_cfa(self, op):
        """
        DWARFv5 extension (sec 2.5.1.3 #15)

        "The DW_OP_call_frame_cfa operation pushes the value of the CFA, obtained
        from the Call Frame Information"
        """
        self._flags |= ExprFlags.REGISTER_UNWIND
        if self._frame is None:
            # We cannot report the CFA because we don't have a backtrace frame to use for unwinding.
            raise Exception(f'Cannot push canonical frame address; no backtrace frame set')
        self.push(self._frame.get_cfa(self.regs))

    # Unimplemented opcodes; not specified in DWARF2; added in DWARF4 or DWARF5..
    _deref_size = _unimplemented_op
    _xderef_size = _unimplemented_op
    _push_object_address = _unimplemented_op
    _call2 = _unimplemented_op
    _call4 = _unimplemented_op
    _call_ref = _unimplemented_op
    _form_tls_address = _unimplemented_op
    _bit_piece = _unimplemented_op
    _implicit_value = _unimplemented_op
    _implicit_pointer = _unimplemented_op
    _addrx = _unimplemented_op # Note: if implemented, remember to set flags.CONST_ADDR a la _addr().
    _constx = _unimplemented_op
    _const_type = _unimplemented_op
    _regval_type = _unimplemented_op
    _deref_type = _unimplemented_op
    _xderef_type = _unimplemented_op
    _convert = _unimplemented_op
    _reinterpret = _unimplemented_op
    _push_tls_address = _unimplemented_op
    _implicit_pointer = _unimplemented_op
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
        return self.regs[DWARFExprMachine.__register_mapping[reg_num]]

    def reg_name(self, reg_num):
        """
        Get the name of a machine register associated with the DWARF register number argument.
        """
        return DWARFExprMachine.__register_mapping[reg_num]

    def mem(self, addr, size=1):
        """
        Get the value contained in SRAM at the specified address.
        """
        self._debugger.verboseprint('Reading ', size, ' bytes at addr 0x', dbg.VHEX4, addr)
        return self._debugger.get_sram(addr, size)

    def flash(self, addr, size=1):
        """
        Get the value contained in flash memory at the specified address.
        """
        self._debugger.verboseprint('Reading ', size, ' bytes at flash 0x', dbg.VHEX4, addr)
        return self._debugger.get_flash(addr, size)

    ### Setup ###

    @classmethod
    def __init_dispatch(cls):
        """
        Initialize the opcode dispatch table the first time we're used.
        """
        d = {
            0x03: cls._addr, # DW_OP_addr
            0x06: cls._deref, # DW_OP_deref
            0x08: cls._const, # DW_OP_const1u
            0x09: cls._const, # DW_OP_const1s
            0x0a: cls._const, # DW_OP_const2u
            0x0b: cls._const, # DW_OP_const2s
            0x0c: cls._const, # DW_OP_const4u
            0x0d: cls._const, # DW_OP_const4s
            0x0e: cls._const, # DW_OP_const8u
            0x0f: cls._const, # DW_OP_const8s
            0x10: cls._const, # DW_OP_constu
            0x11: cls._const, # DW_OP_consts
            0x12: cls._dup, # DW_OP_dup
            0x13: cls._drop, # DW_OP_drop
            0x14: cls._over, # DW_OP_over
            0x15: cls._pick, # DW_OP_pick
            0x16: cls._swap, # DW_OP_swap
            0x17: cls._rot, # DW_OP_rot
            0x18: cls._xderef, # DW_OP_xderef
            0x19: cls._abs, # DW_OP_abs
            0x1a: cls._and, # DW_OP_and
            0x1b: cls._div, # DW_OP_div
            0x1c: cls._minus, # DW_OP_minus
            0x1d: cls._mod, # DW_OP_mod
            0x1e: cls._mul, # DW_OP_mul
            0x1f: cls._neg, # DW_OP_neg
            0x20: cls._not, # DW_OP_not
            0x21: cls._or, # DW_OP_or
            0x22: cls._plus, # DW_OP_plus
            0x23: cls._plus_uconst, # DW_OP_plus_uconst
            0x24: cls._shl, # DW_OP_shl
            0x25: cls._shr, # DW_OP_shr
            0x26: cls._shra, # DW_OP_shra
            0x27: cls._xor, # DW_OP_xor
            0x28: cls._bra, # DW_OP_bra
            0x29: cls._eq, # DW_OP_eq
            0x2a: cls._ge, # DW_OP_ge
            0x2b: cls._gt, # DW_OP_gt
            0x2c: cls._le, # DW_OP_le
            0x2d: cls._lt, # DW_OP_lt
            0x2e: cls._ne, # DW_OP_ne
            0x2f: cls._skip, # DW_OP_skip
            0x90: cls._regx, # DW_OP_regx
            0x91: cls._fbreg, # DW_OP_fbreg
            0x92: cls._bregx, # DW_OP_bregx
            0x93: cls._piece, # DW_OP_piece
            0x94: cls._deref_size, # DW_OP_deref_size
            0x95: cls._xderef_size, # DW_OP_xderef_size
            0x96: cls._nop, # DW_OP_nop
            0x97: cls._push_object_address, # DW_OP_push_object_address
            0x98: cls._call2, # DW_OP_call2
            0x99: cls._call4, # DW_OP_call4
            0x9a: cls._call_ref, # DW_OP_call_ref
            0x9b: cls._form_tls_address, # DW_OP_form_tls_address
            0x9c: cls._call_frame_cfa, # DW_OP_call_frame_cfa
            0x9d: cls._bit_piece, # DW_OP_bit_piece
            0x9e: cls._implicit_value, # DW_OP_implicit_value
            0x9f: cls._stack_value, # DW_OP_stack_value
            0xa0: cls._implicit_pointer, # DW_OP_implicit_pointer
            0xa1: cls._addrx, # DW_OP_addrx
            0xa2: cls._constx, # DW_OP_constx
            0xa3: cls._entry_value, # DW_OP_entry_value
            0xa4: cls._const_type, # DW_OP_const_type
            0xa5: cls._regval_type, # DW_OP_regval_type
            0xa6: cls._deref_type, # DW_OP_deref_type
            0xa7: cls._xderef_type, # DW_OP_xderef_type
            0xa8: cls._convert, # DW_OP_convert
            0xa9: cls._reinterpret, # DW_OP_reinterpret
            0xf2: cls._implicit_pointer, # DW_OP_GNU_implicit_pointer
            0xf3: cls._entry_value, # DW_OP_GNU_entry_value
            0xf4: cls._const_type, # DW_OP_GNU_const_type
            0xf5: cls._regval_type, # DW_OP_GNU_regval_type
            0xf6: cls._deref_type, # DW_OP_GNU_deref_type
            0xf7: cls._convert, # DW_OP_GNU_convert
            0xfa: cls._parameter_ref, # DW_OP_GNU_parameter_ref
        }

        # Add lit0..lit31, reg0..reg31, breg0..breg31 to mappings
        for i in range(0, 32):
            d[i + 0x30] = cls._literal
            d[i + 0x50] = cls._reg_direct
            d[i + 0x70] = cls._reg_lookup

        # Convert the map above into an array for fast lookups.
        cls.__dispatch = (max(d.keys()) + 1) * [ cls._unimplemented_op ]
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

