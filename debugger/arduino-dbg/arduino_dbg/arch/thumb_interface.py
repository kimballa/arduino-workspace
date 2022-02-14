# (c) Copyright 2022 Aaron Kimball

"""
ARM Thumb-specific architecture interface.
"""

import arduino_dbg.arch as arch
import arduino_dbg.debugger as dbg
import arduino_dbg.memory_map as mmap

# Enum for different stack pointer registers implemented on Cortex M-4.
STACK_MSP = 1  # Main stack ptr. Used for all IRQs and handler-mode; can also be used in thread mode.
STACK_PSP = 2  # Process stack ptr. Separate stack pointer that can be used in thread mode.

SPSEL = 0x2  # Bit within CONTROL specifying stack ptr select


@arch.iface
class ArmThumbArchInterface(arch.ArchInterface):
    """
    ARM Thumb-specific implementation of ArchInterface.
    """

    def __init__(self, debugger):
        super().__init__(debugger)
        self._mem_map = None
        self.cur_stack_ptr = STACK_MSP

        # Thumb is 32-bit machine word size.
        assert debugger.get_arch_conf('int_size') == 4

    def memory_map(self):
        if self._mem_map is not None:
            return self._mem_map

        self._mem_map = mmap.MemoryMap()

        logical_data_min = self.debugger.get_arch_conf("DATA_SEGMENT_MIN")
        physical_data_min = self.debugger.get_arch_conf("RAMSTART")

        data_size = self.debugger.get_arch_conf("RAMSIZE")
        code_size = self.debugger.get_arch_conf("FLASHEND") + 1

        logical_code_min = self.debugger.get_arch_conf("TEXT_SEGMENT_MIN")
        physical_code_min = 0

        peripheral_min = self.debugger.get_arch_conf("PERIPHERAL_SEGMENT_MIN")
        peripheral_max = self.debugger.get_arch_conf("PERIPHERAL_SEGMENT_MAX")

        # Flash for .text starts at address 0 but is mem-mapped on-device to use the same access
        # as you would for ordinary SRAM. No Flash-specific accessors required.
        self._mem_map.add_segment(mmap.Segment('.text', mmap.MEM_FLASH, mmap.ACCESS_TYPE_RAM,
                                               logical_code_min, physical_code_min, code_size))

        # .data and .bss start at 0x20000000  and run for RAMSIZE bytes up from there.
        self._mem_map.add_segment(mmap.Segment('.data', mmap.MEM_RAM, mmap.ACCESS_TYPE_RAM,
                                               logical_data_min, physical_data_min, data_size))

        # Other memory-mapped peripherals consume the addr space above 0x30000000
        self._mem_map.add_segment(mmap.Segment('peripherals', mmap.MEM_RAM, mmap.ACCESS_TYPE_RAM,
                                               peripheral_min, peripheral_min,
                                               peripheral_max - peripheral_min + 1))

        self._mem_map.validate()
        return self._mem_map

    def true_pc(self, reg_pc):
        # ARM: low-order bit of 32-bit $PC is the arm/thumb state; should be
        # held to zero for true instruction pointer address.
        return reg_pc & ~0x1

    def mem_to_pc(self, mem_pc):
        return self.true_pc(mem_pc)

    def sym_addr_to_pc(self, sym_pc):
        # Thumb methods will have the lsb of the starting $PC set to 1 but
        # the actual address must be halfword aligned.
        return self.true_pc(sym_pc)

    def is_exception_return(self, lr):
        # ARM: check if bits 31:5 of $LR are all set to 1.
        EXC_RETURN_MASK = 0xFFFFFFE0
        return (lr & EXC_RETURN_MASK) == EXC_RETURN_MASK

    def unwind_exception_registers(self, regs):
        lr_in = regs['PC']
        assert self.is_exception_return(lr_in)
        regs_out = regs.copy()

        # The behavior of this method is described in section 2.3.7 "Exception entry and return"
        # of the Cortex-M4 Devices Generic User Guide (page 2-26).
        #
        # The CPU pushes several registers to stack before entering an exception handler.
        # We've already unwound the "main" stack frame for the IRQ, and now we need to pop
        # the CPU-pushed registers. We also parse $LR to understand some properties of how
        # the unwind operation should proceed.

        # Parsing the $LR value (EXC_RETURN) informs whether we restore the $SP as $MSP or
        # $PSP. We regard $SP as a distinct register but 'true up' $MSP or $PSP at the end
        # of each stack frame unwind operation.
        USE_PSP_FLAG = 0x4      # Switch to $PSP before de-stacking state.
        # THREAD_MODE_FLAG = 0x8  # Return to thread mode rather than handler mode.
                                  # The debugger does not track handler vs thread mode state.
        FPU_PUSHED_FLAG_L = 0x10  # FPU registers were stacked on IRQ entry if this bit is low.

        fpu_registers_pushed = (lr_in & FPU_PUSHED_FLAG_L) == 0
        transfer_to_psp = (lr_in & USE_PSP_FLAG) != 0

        if transfer_to_psp:
            # Intra-IRQ data was on $MSP but the pre-IRQ data was stacked on $PSP and
            # we return there now.
            assert self.cur_stack_ptr == STACK_MSP  # All handler mode is on $MSP, and IRQ return
                                                    # implies operating in handler mode.
            sp = regs['PSP']  # Ignore prior $MSP-based value for $SP.
            regs_out['CTRL'] = regs['CTRL'] | SPSEL  # Set SPSEL bit.
            self.cur_stack_ptr = STACK_PSP
            self.debugger.verboseprint(f'Switching to $PSP: 0x{sp:08x}')
        else:
            # continue operating on same $SP as before. (Which we know was $MSP as we're in an IRQ.)
            sp = regs['SP']

        push_word_len = self.debugger.get_arch_conf('push_word_len')

        # Pop these registers in order.
        for pop_reg in ['r0', 'r1', 'r2', 'r3', 'r12', 'LR', 'PC', 'CPSR']:
            regs_out[pop_reg] = self.debugger.get_sram(sp, push_word_len)
            if pop_reg in ['LR', 'PC']:
                regs_out[pop_reg] = self.true_pc(regs_out[pop_reg])

            self.debugger.verboseprint(
                "Exception destack: ", pop_reg, " <-- ", dbg.VHEX8, regs_out[pop_reg])
            sp += push_word_len

        if fpu_registers_pushed:
            # We do not monitor the FPU registers in this debugger. But if the FPU
            # registers have been stacked, we need to at least adjust $SP past them.
            # Fig 2-3 in Cortex-M4 Devices Generic User Guide shows 16 32-bit FPU registers
            # stacked, plus FPSCR, plus a mandatory spacer entry (in addition to any aligner
            # controlled by STKALIGN). Thus, we add 18 x 4 bytes to the address to 'pop'
            # all of these at once.
            self.debugger.verboseprint("Exception destack: popping (discarding) 18 stacked FPU registers")
            sp += (18 * push_word_len)

        STKALIGN = 0x200  # bit 9 of stacked xPSR (CCR / Configuration & Control Register).
        control_stkalign_bit = regs['CPSR'] & STKALIGN  # Get 'true' STKALIGN value.

        # STKALIGN bit in general controls whether the stack is 8-byte aligned (1) or if (0),
        # allows ABI violation and the system uses 4-byte aligned stack. The stacked CPSR
        # uses this bit to indicate whether it had to push an aligner word or not (see table 4-20
        # in Cortex-M4 Devices Generic User Guide).
        pushed_aligner = regs_out['CPSR'] & STKALIGN
        regs_out['CPSR'] &= ~STKALIGN
        regs_out['CPSR'] |= control_stkalign_bit  # Restore actual STKALIGN bit

        if control_stkalign_bit == STKALIGN:
            assert sp % 8 == 0  # ARM ABI: Stack must be 8-byte aligned on stack frame entry.

        if pushed_aligner:
            # The CPU needed to add a 4-byte spacer before exn entry. Pop the spacer.
            # See User Guide sec 4.3.7 "Configuration and Control Register" and table 4-20.
            self.debugger.verboseprint("Exception destack: popping 4-byte aligner")
            self.debugger.verboseprint("Got STKALIGN flag with $SP=", dbg.VHEX8, sp)
            sp += push_word_len

        regs_out['SP'] = sp
        self.debugger.verboseprint("Post-exception SP: ", dbg.VHEX8, regs_out['SP'])

        return regs_out

    def finish_register_unwind(self, regs):
        if self.cur_stack_ptr == STACK_MSP:
            regs['MSP'] = regs['SP']  # Keep $MSP in sync with $SP
        else:
            regs['PSP'] = regs['SP']  # Keep $PSP in sync with $SP

        return regs

    def begin_backtrace(self, regs):
        # The SPSEL bit in the CONTROL register tells us which stack pointer we are operating
        # with. This can be switched as we unwind the stack based on $LR in exception return,
        # but at top-of-stack we can trust CONTROL to tell us what to do.
        ctrl_reg = regs['CTRL']
        if ctrl_reg & SPSEL:
            # We are operating on the process stack ptr.
            self.cur_stack_ptr = STACK_PSP
            self.debugger.verboseprint('Stack operating on $PSP')
        else:
            # We are operating on the main stack ptr.
            self.cur_stack_ptr = STACK_MSP
            self.debugger.verboseprint('Stack operating on $MSP')
