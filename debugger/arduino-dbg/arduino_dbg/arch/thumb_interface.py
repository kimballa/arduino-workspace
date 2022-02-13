# (c) Copyright 2022 Aaron Kimball

"""
ARM Thumb-specific architecture interface.
"""

import arduino_dbg.arch as arch
import arduino_dbg.debugger as dbg
import arduino_dbg.memory_map as mmap


@arch.iface
class ArmThumbArchInterface(arch.ArchInterface):
    """
    ARM Thumb-specific implementation of ArchInterface.
    """

    def __init__(self, debugger):
        super().__init__(debugger)
        self._mem_map = None

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
        assert self.is_exception_return(regs['PC'])
        regs_out = regs.copy()

        # The behavior of this method is described in section 2.3.7 "Exception entry and return"
        # of the Cortex-M4 Devices Generic User Guide (page 2-26).

        # TODO(aaron): Parsing the $LR value (EXC_RETURN) informs whether we restore the $SP
        # as $MSP or $PSP. We do not differentiate between these here but just regard $SP
        # as a distinct register. If debugging an embedded RTOS, we should be sensitive to
        # which stack pointer we are restoring. (nb some of these use the lsb of $LR, which
        # we may have already set to zero via true_pc().)

        # TODO(aaron): Do we care about FPU registers and restoring them?
        # If the FPU registers have been stacked, we need to at least adjust $SP past them.


        push_word_len = self.debugger.get_arch_conf('push_word_len')
        sp = regs['SP']

        # Pop these registers in order.
        for pop_reg in ['r0', 'r1', 'r2', 'r3', 'r12', 'LR', 'PC', 'CPSR']:
            regs_out[pop_reg] = self.debugger.get_sram(sp, push_word_len)
            if pop_reg in ['LR', 'PC']:
                regs_out[pop_reg] = self.true_pc(regs_out[pop_reg])

            self.debugger.verboseprint(
                "Exception destack: ", pop_reg, " <-- ", dbg.VHEX8, regs_out[pop_reg])
            sp += push_word_len

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
        # TODO(aaron): read the `SPSEL` bit in the `CONTROL` register to determine whether MSP or
        # PSP is the active stack pointer.
        regs['MSP'] = regs['SP']  # Keep $MSP in sync with $SP
        return regs

