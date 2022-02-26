# (c) Copyright 2021 Aaron Kimball
"""
CPU Architecture-specific concerns.
"""

from arduino_dbg.term import MsgLevel
import arduino_dbg.memory_map as mmap


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
    # populates ARCH_INTERFACES via @iface decorators.
    import arduino_dbg.arch.avr_interface       # noqa: F401
    import arduino_dbg.arch.thumb_interface     # noqa: F401

    __arch_interfaces_loaded = True  # Only need to run this method once.


def inject_arch_interface(name, cls):
    """
    Reprogram a name-to-class binding. (i.e., for unit testing)
    """
    global ARCH_INTERFACES

    load_arch_interfaces()  # Set up main bindings first.
    ARCH_INTERFACES[name] = cls


class ArchNotSupportedError(Exception):
    """ Architecture / ArchInterface does not support a particular method. """
    pass


class HWBreakpointsFullError(Exception):
    """
    Hardware breakpoint configuration does not have spare registers.

    A request to add a hardware breakpoint cannot be fulfilled until a register
    is freed by removing a different configured hardware breakpoint.
    """
    pass


class BreakpointAddrExistsError(Exception):
    """
    A given address is already in the breakpoint watch list.
    """
    pass


class BreakpointNotEnabledError(Exception):
    """ A given breakpoint isn't enabled so we cannot disable it. """
    pass


class BreakpointScheduler(object):
    """
    Abstract class interface where implementations contain logic to map logical breakpoint
    definitions to specific hardware breakpoint comparator registers on the target system.
    """

    def schedule_bp(breakpoint):
        """
        Map a breakpoint into one of the breakpoint-compatible comparators.

        This may move other breakpoints into different breakpoint registers as required,
        although it may not disable another breakpoint to make room for this one.
        """
        raise Exception("Unimplemented")

    def deschedule_bp(breakpoint):
        """
        Remove a breakpoint from the running system.

        This may move other breakpoints into more advantageous registers if the descheduling
        operation frees up such an advantageous location.
        """
        raise Exception("Unimplemented")

    def sync(self):
        """ Ensure hardware bp registers on device match our understanding of the state """
        raise Exception("Unimplemented")

    def get_num_hardware_breakpoints_used(self):
        return 0




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
        self.debugger.msg_q(MsgLevel.WARN, 'Warning: No memory model defined for this architecture')
        return mmap.MemoryMap()  # Return empty memory model.

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

    def finish_register_unwind(self, regs):
        """
        Perform any final post-processing needed at the end of CFI / unwind_registers() processing
        for a frame.

        Modifies 'regs' in-place, if at all.
        Returns 'regs'.
        """
        return regs

    def begin_backtrace(self, regs):
        """
        Reset any arch-specific state when beginning a backtrace at the top of the stack.
        """
        pass

    def parse_arch_specs(self, arch_specs_strs):
        """
        In response to the DBG_OP_ARCH_SPEC command, the server will return a list of strings
        describing any run-time-discernable state needed by the debugger. Parse the arch
        spec data here. The ArchInterface is responsible for storing and parsed config state
        and providing appropriate getters to the Debugger, or incorporating said state in how it
        implements other arch-specific methods.
        """
        pass  # Default: Nothing to do.

    def _get_arch_specs(self):
        """
        Protected method to retrieve arch specs from device if not already loaded.
        """
        arch_1 = self.debugger.get_conf("arduino.arch")
        specs_lst = self.debugger.get_arch_specs()
        arch_2 = self.debugger.get_conf("arduino.arch")
        if arch_1 != arch_2:
            # The debugger has pre-processed the ARCH_SPEC response and has updated its arduino.arch
            # field in response. Architecture has changed (from 'auto' to a defined architecture).
            # We may be in an ArchInterface that has been replaced by the debugger. Do not continue
            # processing.
            raise Exception("Architecture definition has changed. Please retry command.")

        self.parse_arch_specs(specs_lst)

    def get_num_hardware_breakpoints(self):
        """
        Return number of hardware breakpoint slots/comparators available.
        """
        return 0

    def get_num_hardware_breakpoints_used(self):
        """
        Return number of hardware breakpoint comparators in use.
        """
        return 0

    def create_hw_breakpoint(self, breakpoint):
        """
        Create a hardware breakpoint on the specified address.
        """
        raise Exception("Hardware breakpoints not supported")

    def remove_hw_breakpoint(self, breakpoint):
        """
        Remove the hardware breakpoint for the specified address.
        """
        raise Exception("Hardware breakpoints not supported")

    def sync_hw_breakpoints(self):
        """
        Ensure hardware breakpoint reigsters match locally-tracked definitions for state.
        """
        pass  # By default there is nothing to do to sync as this base impl doesn't track hw breakpoints.

    def breakpoint_scheduler(self):
        """
        Return the active breakpoint scheduler for this device, or None if hardware breakpoints
        are not supported.
        """
        return None

    def print_cpu_stats(self):
        """
        Print CPU information.
        """
        archconf = self.debugger.get_arch_conf
        self.debugger.msg_q(MsgLevel.INFO, f'Architecture: {self.debugger.get_conf("arduino.arch")}')
        self.debugger.msg_q(MsgLevel.INFO, f'ISA: {archconf("instruction_set")}')
        self.debugger.msg_q(MsgLevel.INFO, f'Clock speed: {archconf("clock_freq")/1000000} MHz')
        self.debugger.msg_q(MsgLevel.INFO, f'Endian: {archconf("endian")}')
        self.debugger.msg_q(MsgLevel.INFO, f'RAM: 0x{archconf("RAMSIZE"):x}')
        self.debugger.msg_q(MsgLevel.INFO, f'Word size: {archconf("push_word_len")}')
        self.debugger.msg_q(MsgLevel.INFO, f'General-purpose registers: {archconf("general_regs")}')
        self.debugger.msg_q(MsgLevel.INFO, f'Supports single-step: {archconf("single_step_supported")}')
        self.debugger.msg_q(MsgLevel.INFO, f'Hardware breakpoints: {self.get_num_hardware_breakpoints()}')

    @staticmethod
    def make_arch_interface(debugger):
        """
        Factory method to provide the correct ArchInterface implementation for the
        current debugger config.
        """
        iface_name = debugger.get_arch_conf("arch_interface")
        if iface_name is None:
            debugger.msg_q(MsgLevel.WARN, f"Warning: No architecture interface specified")
            return ArchInterface(debugger)  # Attempt to use the default ArchInterface.
        elif iface_name not in ARCH_INTERFACES:
            debugger.msg_q(MsgLevel.WARN, f"Warning: Unknown architecture interface: {iface_name}")
            return None

        debugger.verboseprint(f'Loading debugger architecture interface: {iface_name}')
        return ARCH_INTERFACES[iface_name](debugger)

