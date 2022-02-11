# (c) Copyright 2021 Aaron Kimball
"""
CPU Architecture-specific concerns.
"""

from arduino_dbg.term import MsgLevel


# Map from class names to classes that fulfill the ArchInterface contract.
ARCH_INTERFACES = {}
__arch_interfaces_loaded = False


def iface(cls):
    """
    Decorator for ArchInterface subclasses that adds the subclass to the set that can be spawned
    based on the selected arch_conf.

    e.g.:

    @iface
    class MyArchInterface(ArchInterface):
        pass
    """
    ARCH_INTERFACES[cls.__name__] = cls
    return cls


def load_arch_interfaces():
    """
    Load all the architecture interface modules, which triggers them to
    each call register_arch_interface() with their specific class.
    """
    global __arch_interfaces_loaded
    if __arch_interfaces_loaded:
        return  # No further work to do.

    # We don't literally use these modules in this method but their loading
    # populates ARCH_INTERFACES via calls to register_arch_interface.
    import arduino_dbg.arch.avr_interface       # noqa: F401
    import arduino_dbg.arch.thumb_interface     # noqa: F401

    __arch_interfaces_loaded = True  # Only need to run this method once.


class ArchNotSupportedError(Exception):
    """ Architecture / ArchInteface does not support a particular method. """
    pass


class ArchInterface(object):
    """
    A module to hold various methods invoked by the debugger that need to perform
    differently depending on the CPU architecture.
    """

    def __init__(self, debugger):
        self.debugger = debugger

    def __repr__(self):
        return self.__class__.__name__

    def memory_map(self):
        """
        Return the memory map for this device.
        """
        raise ArchNotSupportedError('No memory model defined for this architecture')

    def reg_word_mask(self):
        """
        Return a bitmask representing the width of one machine register.
        """
        w = self.reg_width_bytes()
        if w == 1:
            return 0xFF
        elif w == 2:
            return 0xFFFF
        elif w == 4:
            return 0xFFFFFFFF
        elif w == 8:
            return 0xFFFFFFFFFFFFFFFF
        else:
            raise ArchNotSupportedError(f'Unsupported machine word width: {w}')

    def reg_width_bytes(self):
        """
        Return the width in bytes of one general-purpose machine register.
        """
        return self.debugger.get_arch_conf("push_word_len")

    def sp_width_bytes(self):
        """
        Return the width in bytes of the stack pointer machine register.
        """
        return self.reg_width_bytes()


    def true_pc(self, reg_pc):
        """
        Given a $PC value word as read from register, return the true $IP memory address
        this represents.
        """
        return reg_pc

    def mem_to_pc(self, mem_pc):
        """
        Given a $PC value word as read linearly from RAM (e.g., when reading successive
        bytes from the stack representing the return addr), convert to the true $IP
        memory address this represents.
        """
        return mem_pc

    def sym_addr_to_pc(self, sym_pc):
        """
        Given a $PC value as read from a .symtab entry (elf_sym.entry['st_value']) as the first
        $PC within a given method, convert it to the actual starting address of the method.
        """
        return sym_pc

    def stack_frame_size(self, frame, regs_in):
        """
        Given a CallFrame with a program counter ($PC) somewhere within the body of the `frame.sym`
        method, determine the size of the current stack frame at that point and return it.

        i.e., if SP is 'x' and this method returns 4, then 4 bytes of stack RAM have been
        filled by the method (x+1..x+4) and the return address is just below that on the stack
        (e.g., starting at x+5, in a descending stack).

        ArchInterface implementations may use one or more methods to determine stack frame
        size, such as frame pointer examination (where frame pointers are mandated by ABI),
        CFA record lookup, or prologue analysis.

        This returns the size of the stack frame for the current method at a particular
        intra-method program point identified by $PC.

        @param frame -- The CallFrame to analyze.
        @param regs_in -- The register snapshot at $PC.
        """

        size_by_cfi = self.stack_frame_size_by_cfi(frame, regs_in)
        if size_by_cfi is not None:
            return size_by_cfi  # Found it!

        # We don't have any other mechanism to deduce this value.
        raise ArchNotSupportedError()

    def stack_frame_size_by_cfi(self, frame, regs_in):
        """
        If we have the current register snapshot (regs_in) and a CallFrame with a CFI record,
        we can unwind the registers in an architecture-neutral fashion and compare the value
        of $SP before and after unwinding.

        Returns the stack frame size in bytes if this can be deduced from CFI records,
        otherwise returns None.
        """
        # Try using arch-neutral call-frame analysis
        regs_out = frame.unwind_registers(regs_in)
        if regs_out is not None and regs_in is not None and 'SP' in regs_out and 'SP' in regs_in:
            return abs(regs_out['SP'] - regs_in['SP'])

        return None


    def patch_debug_frame(self, sym, frame_info, pc):
        """
        On some architectures, the prologue may save state to the stack that is not
        accounted for in CFA records in .debug_frame. (e.g., on AVR, ISRs save $SREG with
        a PUSH but this does not add 1 to the CFA offset.)

        Perform any architecture-specific fix-ups to create correct CFA calculations
        in the face of any bugs in gcc when generating .debug_frame records.

        Each symbol should be processed at most once; we set `sym.isr_frame_ok = True`
        after processing the frame, modifying frame_info in place as needed, or leaving it
        as-is after we've validated its accuracy.
        """

        # Default implementation does not change frame_info.
        sym.isr_frame_ok = True

    def is_exception_return(self, lr):
        """
        On some architectures (ARM), the link register holds a special value when returning
        from an exception, which triggers a further hardware-defined stack unwind process
        to restore the pre-exception state.

        This function returns true if its argument (the $LR value) represents an exception
        return flag.
        """
        return False  # By default, architectures do not have special exception return process.

    def unwind_exception_registers(self, regs):
        """
        If is_exception_return() returned true, this function can be called by
        CallFrame.unwind_registers() to perform the further unwinding necessary to
        fully restore the pre-exception state.

        This function takes the register snapshot after the CFI-driven register unwind is
        complete and returns a new register snapshot representing the fully-unwound state.

        If is_exception_return() would have returned False, this method's response is undefined.
        """
        return regs  # By default, no further action is needed.


    @staticmethod
    def make_arch_interface(debugger):
        """
        Factory method to provide the correct ArchInterface implementation for the
        current debugger config.
        """
        iface_name = debugger.get_arch_conf("arch_interface")
        if iface_name not in ARCH_INTERFACES:
            debugger.msg_q(MsgLevel.WARN, f"Warning: Unknown architecture interface: {iface_name}")
            return None

        debugger.verboseprint(f'Loading debugger architecture interface: {iface_name}')
        return ARCH_INTERFACES[iface_name](debugger)

