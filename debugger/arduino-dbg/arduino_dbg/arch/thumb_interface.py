# (c) Copyright 2022 Aaron Kimball

"""
ARM Thumb-specific architecture interface.
"""

import arduino_dbg.arch as arch
import arduino_dbg.debugger as dbg
import arduino_dbg.memory_map as mmap
from arduino_dbg.term import MsgLevel


ARM_CAPABILITIES = [
    'arm-cortex-hardware-breakpoint-dwt',  # Cortex M3/M4 hardware breakpoints in FPB & DWT.
    'arm-cortex-hardware-breakpoint-fpb',
    'arm-irq-backtrace',  # ARM-specific IRQ stack frame unwinding
]

# Enum for different stack pointer registers implemented on Cortex M-4.
STACK_MSP = 1  # Main stack ptr. Used for all IRQs and handler-mode; can also be used in thread mode.
STACK_PSP = 2  # Process stack ptr. Separate stack pointer that can be used in thread mode.

SPSEL = 0x2  # Bit within CONTROL specifying stack ptr select

# Cortex-M FPB comparator count is specified in bits of FP_CTRL. There may be between 0 and 8
# such (32-bit) comparators, which are sequentially memory-mapped starting with FP_COMP0.
FP_COMP0_addr = 0xE0002008  # 1st FPB comparator. Max is FP_COMP7.

# Cortex-M DWT unit memory mapping:
DWT_COMP0_addr = 0xE0001020  # 1st DWT comparator. Max is FP_COMP3.
                             # DWT registers are sequentially mem-mapped as an array of tuples of
                             # {COMP, MASK, FUNC, <reserved>} (4 bytes per register)
DWT_MASK_offset = 0x4
DWT_FUNC_offset = 0x8
DWT_struct_size = 0x10  # 4 words per DWT comparator register set.


class CortexBreakpointScheduler(arch.BreakpointScheduler):
    """
    Cortex M-series CPU breakpoint scheduler: maps addresses where the user wants
    to set a breakpoint into available breakpoint comparators.

    This scheduler can make use of the FPB unit and the DWT unit's comparators to
    enable a collection of breakpoint and watchpoint values.
    """

    def __init__(self, thumb_arch_interface):
        self.arch_iface = thumb_arch_interface
        self.debugger = self.arch_iface.debugger

        self.loaded_params = False

        self.fpb_comparators = []
        self.dwt_comparators = []

    def __repr__(self):
        strs = []
        strs.append("Cortex breakpoint scheduler")
        if not self.loaded_params:
            strs.append("(uninitialized)")
        else:
            fpb_cnt = len(self.fpb_comparators)
            dwt_cnt = len(self.dwt_comparators)
            fpb_used = self._num_fpb_in_use()
            dwt_used = self._num_dwt_in_use()
            strs.append(f'Registers: FPB={fpb_used}/{fpb_cnt}; DWT={dwt_used}/{dwt_cnt}')
            strs.append('')

            for i in range(0, len(self.fpb_comparators)):
                bp = self.fpb_comparators[i]
                if bp is None:
                    strs.append(f'FPB #{i}: ---')
                else:
                    strs.append(f'FPB #{i}: 0x{bp.pc:08x}')
            strs.append('')

            for i in range(0, len(self.dwt_comparators)):
                bp = self.dwt_comparators[i]
                if bp is None:
                    strs.append(f'DWT #{i}: ---')
                else:
                    strs.append(f'DWT #{i}: 0x{bp.pc:08x}')

        return '\n'.join(strs)

    def _num_fpb_in_use(self):
        """ Return number of FPB registers in use. """
        return len(list(filter(lambda x: x is not None, self.fpb_comparators)))

    def _num_dwt_in_use(self):
        """ Return number of DWT registers in use. """
        return len(list(filter(lambda x: x is not None, self.dwt_comparators)))

    def _load_params(self):
        """
        Get parameters from arch_iface describing the configuration of the breakpoint unit.
        Delayed from c'tor until data is necessary so that we can instantiate this object w/o
        using it in an offline debugger setup.
        """
        if self.loaded_params:
            return

        self.arch_iface.get_num_hardware_breakpoints()  # Trigger parameter data load from remote
        num_fpb = self.arch_iface.arch_specs['fpb_code_addrs']
        num_dwt = self.arch_iface.arch_specs['dwt_num_comparators']

        # Initialize arrays
        self.fpb_comparators = num_fpb * [None]
        self.dwt_comparators = num_dwt * [None]

        self.loaded_params = True


    def schedule_bp(self, breakpoint):
        """
        Map a breakpoint into one of the breakpoint-compatible comparators.

        We may choose to relocate other breakpoints or watchpoints from their current
        comparator register into another comparator that is compatible with that bp's
        needs if it frees up a register necessary for this one. (For example, a breakpoint 'X'
        may be installed in an iAddr-compatible comparator in the DWT, and we may move X
        into a free comparator in the FPB to reuse the DWT's comparator for a new data watchpoint
        provided as the argument to this method.)

        We need to respect constraints of the system memory map and peripheral operating
        architected semantics:
        * FPB FP_COMPn regs can only operate on addrs in the code (.text) region (0x00000000...0x1FFFFFFF)
          in FPB v1. (They can operate on full 32bit addrs in FPB v2.)
        * DWT DWT_COMPn regs can be used for data or instruction addr watching, on any 32-bit addr,
          and thus can be used for breaking on SRAM-resident code. Note that DWT_COMPn breakpt
          fires *after* the instruction at the watched $PC is evaluated, rather than before as FPB
          does. Prefer to use FPB.
        * Addresses in FPB registers omit the 2 lsbs and flags can trigger on addresses xxxx00, xxxx10,
          or both, offering compaction opportunities.
        * Addresses in DWT COMPn registers have associated MASKn registers, which offer compaction
          opportunities for sequential breakpoints.
        * FPB operates on memory addresses ($PC[0] <- 0). DWT operates on $PC register values
          ($PC[0] <- 1 for Thumb-state code). (TODO... check that??!?)
          .

        """
        CODE_MAX = 0x1FFFFFFF

        assert breakpoint.is_dynamic
        self._load_params()

        addr = breakpoint.pc
        assert addr != 0x0

        # Don't double-enable an address; reject addresses we are already watching.

        for maybe_bp in self.fpb_comparators + self.dwt_comparators:
            if maybe_bp is None:
                continue
            elif maybe_bp is breakpoint:
                # Literally the same breakpoint as one we've already got.
                # Just do nothing.
                return
            elif maybe_bp.pc == addr:
                # Second BP at same addr as an existing one... Fail.
                raise arch.BreakpointAddrExistsError()

        if addr < CODE_MAX or self.arch_iface.arch_specs['fpb_version'] == 2:
            # Address can be tracked in FPB. Try using these hw bp's first.
            try:
                fpb_slot = self.fpb_comparators.index(None)
                self.fpb_comparators[fpb_slot] = breakpoint
                self._program_fpb_breakpoint(True, fpb_slot, addr)
                return
            except ValueError:
                # FPB does not have a free slot.
                pass

        # Could not install bp in FPB. (Full or addr out-of-range.)
        # $PC in .code or .data can be tracked in DWT.
        try:
            dwt_slot = self.dwt_comparators.index(None)
            self.dwt_comparators[dwt_slot] = breakpoint
            self._program_dwt_breakpoint(True, dwt_slot, addr)
        except ValueError:
            # DWT does not have a free slot.
            raise arch.HWBreakpointsFullError("No hardware breakpoint slot available")


    def deschedule_bp(self, breakpoint):
        """
        Remove a breakpoint from the running system.
        """
        assert breakpoint.is_dynamic
        self._load_params()

        # Check if it's in FPB:
        if breakpoint in self.fpb_comparators:
            fpb_slot = self.fpb_comparators.index(breakpoint)
            self.fpb_comparators[fpb_slot] = None
            self._program_fpb_breakpoint(False, fpb_slot, None)  # null-out this FPB register value.

            if self._num_dwt_in_use() > 0:
                # Now that we have a free FPB slot, promote a DWT breakpoint to the more precise
                # FPB breakpoint registers. DWT registers trigger async breakpoints after the
                # specified instruction.
                for i in range(0, len(self.dwt_comparators)):
                    if self.dwt_comparators[i] is not None:
                        self._promote_dwt_to_fpb(i, fpb_slot)
                        break

            return

        # Not in FPB. Try to locate the breakpoint in the DWT.
        if breakpoint not in self.dwt_comparators:
            # Not there either. What?
            raise arch.BreakpointNotEnabledError()

        dwt_slot = self.dwt_comparators.index(breakpoint)
        self.dwt_comparators[dwt_slot] = None
        self._program_dwt_breakpoint(False, dwt_slot, None)

    def sync(self):
        self._load_params()

        # Ensure FPB registers match local defs for FPB-tracked breakpoints
        for i in range(0, len(self.fpb_comparators)):
            fpb_bp = self.fpb_comparators[i]
            if fpb_bp is None:
                self._program_fpb_breakpoint(False, i, None)
            else:
                self._program_fpb_breakpoint(True, i, fpb_bp.pc)

        # Ensure DWT registers match local defs for DWT-tracked breakpoints
        for i in range(0, len(self.dwt_comparators)):
            dwt_bp = self.dwt_comparators[i]
            if dwt_bp is None:
                self._program_dwt_breakpoint(False, i, None)
            else:
                self._program_dwt_breakpoint(True, i, dwt_bp.pc)

    def get_num_hardware_breakpoints_used(self):
        self._load_params()

        # Return all non-None comparator slots.
        lst = []
        lst.extend(self.fpb_comparators)
        lst.extend(self.dwt_comparators)
        return len(list(filter(lambda v: v is not None, lst)))


    def _promote_dwt_to_fpb(self, dwt_slot, fpb_slot):
        """
        Move a breakpoint definition from the DWT to the FPB.

        Since DWT registers trigger async breakpoints and FPB is synchronous, we prefer to bunch up
        our breakpoints in the FPB if slots are available. This can be used to "compact" our
        breakpoints after FPB slots are opened up.

        Helper method typically invoked by deschedule_bp() to rebalance registers.
        """

        dwt_bp = self.dwt_comparators[dwt_slot]
        assert dwt_bp is not None
        assert dwt_bp.pc != 0x0
        addr = dwt_bp.pc

        self._program_fpb_breakpoint(True, fpb_slot, addr)
        self._program_dwt_breakpoint(False, dwt_slot, None)

        self.fpb_comparators[fpb_slot] = dwt_bp
        self.dwt_comparators[dwt_slot] = None

        self.debugger.msg_q(MsgLevel.LOW,
                            f'Promoted breakpoint at $PC 0x{addr:08x} to precise bp register.')


    def _program_fpb_breakpoint(self, is_enable, reg_id, pc_addr):
        """
        Program a breakpoint comparator register in the FPB.

        * is_enable: True to enable breakpoint, False to clear an existing one. If False, ignore
          pc_addr.
        * reg_id: The index into the array of FP_COMPn comparator registers.
        * pc_addr: the $PC to break on.
        """
        reg_addr = FP_COMP0_addr + (4 * reg_id)  # register addr is array index starting from FP_COMP0.

        if not is_enable:
            # Zero out the comparator register.
            self.debugger.verboseprint(
                f'Disabling FPB breakpoint {reg_id} @ 0x{reg_addr:x}')
            self.debugger.set_sram(reg_addr, 0, 4)  # Set 4-byte word to all zeroes.
        else:
            self.debugger.verboseprint(
                f'Setting FPB breakpoint {reg_id} @ 0x{reg_addr:x}: $PC=0x{pc_addr:x}')
            # Enable the register. Specific bits to set are FPB revision-dependent.
            fpb_version = self.arch_iface.arch_specs['fpb_version']
            if fpb_version == 1:
                # Register layout:
                # 31:30 -- 2-bit REPLACE flags
                #    29 -- Reserved
                # 28: 2 -- PC_ADDR[28:2]
                #     1 -- Reserved
                #     0 -- ENABLE
                comparator_val = (pc_addr & 0x1FFFFFFC) | 0x1  # Set PC_ADDR and ENABLE
                # Set REPLACE flags:
                if pc_addr & 0x2:
                    comparator_val |= 0x80000000  # BP on instr at '000':pc_addr_part:'10'
                else:
                    comparator_val |= 0x40000000  # BP on instr at '000':pc_addr_part:'00'

                # TODO(aaron): If we're multiplexing two adjacent addrs onto the same register,
                # we need a flag arg to this method to set REPLACE bits to b'11' (0xC0000000)

                self.debugger.set_sram(reg_addr, comparator_val, 4)  # Set 4-byte comparator reg.
            elif fpb_version == 2:
                # FPB v2 register format depends on whether this FPB supports address remapping.
                # (tracked as boolean: arch_iface.arch_specs['fpb_remap_supported'])
                # Although in all cases where a breakpoint is enabled, 31:1 are PC_ADDR and
                # lsb is '1' for BP_Enabled.
                #
                # If BP_Enabled is 0 and flashpatch is supported, must also set msb to 0 to
                # fully disable usage, otherwise (if msb is 1) then flash patching of the
                # specified addr will be enabled.

                comparator_val = pc_addr & 0xFFFFFFFE | 0x1  # Set PC_ADDR and ENABLE.
                self.debugger.set_sram(reg_addr, comparator_val, 4)  # Set 4-byte comparator reg.
            else:
                raise Exception(f'Cannot program FPB breakpoint on FPB version {fpb_version}')


    def _program_dwt_breakpoint(self, is_enable, reg_id, pc_addr):
        """
        Program a comparator in the DWT to operate as a breakpoint using PC-match mode.

        * is_enable: True to enable breakpoint, False to clear an existing one. If False, ignore
          pc_addr.
        * reg_id: The index into the array of DWT_COMPn comparator register structs.
        * pc_addr: the $PC to break on.
            Note that DWT triggers a breakpoint *after* the specified opcode executes, not before as
            FPB does.

        """

        comp_reg_addr = DWT_COMP0_addr + (reg_id * DWT_struct_size)
        mask_reg_addr = comp_reg_addr + DWT_MASK_offset
        func_reg_addr = comp_reg_addr + DWT_FUNC_offset

        if not is_enable:
            self.debugger.verboseprint(
                f'Disabling DWT breakpoint {reg_id} @COMP=0x{comp_reg_addr:x}')
            self.debugger.set_sram(comp_reg_addr, 0, 4)
            self.debugger.set_sram(func_reg_addr, 0, 4)  # func = b'0000' => disabled.
        else:
            # Set pre-masked 4-byte comparator reg.
            self.debugger.verboseprint(
                f'Setting DWT breakpoint {reg_id} @COMP=0x{comp_reg_addr:x}: $PC=0x{pc_addr:x}')
            self.debugger.msg_q(
                MsgLevel.WARN,
                f'Hardware breakpoint for 0x{pc_addr:x} will halt a few cycles after '
                f'instruction execution,\n'
                f'via async interrupt driven by DWT.'
                f'\n\n'
                f'For more precise breakpoint behavior, disable a breakpoint in the FPB.\n'
                f'FPB breakpoints can be viewed with `breakpoint list extended`.')

            self.debugger.set_sram(comp_reg_addr, pc_addr & 0xFFFFFFFE, 4)
            self.debugger.set_sram(mask_reg_addr, 0x1, 4)  # Set mask to ignore LSB of $PC.
            self.debugger.set_sram(func_reg_addr, 0x4, 4)  # Set FUNC=b0100, Iaddr watchpoint dbg event.
                                                           # Other fields (DATAVMATCH, CYCMATCH..) = 0.


@arch.iface
class ArmThumbArchInterface(arch.ArchInterface):
    """
    ARM Thumb-specific implementation of ArchInterface.
    """

    def __init__(self, debugger):
        super().__init__(debugger)
        self._mem_map = None
        self.cur_stack_ptr = STACK_MSP
        self.arch_specs = None

        # TODO(aaron): Probably needs to be parameterized as there are ARM Thumb-based
        # systems that are not necessarily Cortex M-series CPUs.
        self._breakpoint_scheduler = CortexBreakpointScheduler(self)

        # Thumb is 32-bit machine word size.
        assert debugger.get_arch_conf('int_size') == 4

    def __repr__(self):
        return f'{self.__class__.__name__} {self.arch_specs}'

    def get_capabilities_list(self):
        """ List any runtime-advertised capabilities. """
        return ARM_CAPABILITIES

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

    def parse_arch_specs(self, arch_specs_strs):
        # Format returned by SAMD51:
        #   CPUID
        #   FP_CTRL register (flashpatch/breakpoint unit capabilities)
        #   FP_REMAP register (More FPB capabilities detection)
        #   DWT_CTRL register (data watchpoint & trace unit capabilities)

        CPUID = int(arch_specs_strs[0], base=16)
        FP_CTRL = int(arch_specs_strs[1], base=16)
        FP_REMAP = int(arch_specs_strs[2], base=16)
        DWT_CTRL = int(arch_specs_strs[3], base=16)

        # Determine implementation version of Flashpatch/break unit; FP_COMPn register
        # format is different on each.
        FPB_REV_MASK = 0xF0000000
        FPB_REV_OFFSET = 28
        fpb_rev_field = (FP_CTRL & FPB_REV_MASK) >> FPB_REV_OFFSET
        if fpb_rev_field == 0:
            fpb_version = 1
        elif fpb_rev_field == 1:
            fpb_version = 2
        else:
            fpb_version = -1
            self.debugger.msg_q(MsgLevel.WARN,
                                f'Unknown flashpatch unit version with bits 0x{fpb_rev_field:x}')

        # The NUM_CODE field is split into two separate sections in the register
        # that we need to recombine to get the number of code addr comparators.
        FPB_NUM_CODE_HI_MASK = 0x7000
        FPB_NUM_CODE_HI_OFFSET = 8

        FPB_NUM_CODE_LO_MASK = 0xF0
        FPB_NUM_CODE_LO_OFFSET = 4

        fpb_code_addrs = (((FP_CTRL & FPB_NUM_CODE_HI_MASK) >> FPB_NUM_CODE_HI_OFFSET) |
                          ((FP_CTRL & FPB_NUM_CODE_LO_MASK) >> FPB_NUM_CODE_LO_OFFSET))

        # The NUM_LIT field gives the number of literal address comparators in the FPB
        # unit. Literal comparators are numbered sequentially after the code addr comparators.
        FPB_NUM_LIT_MASK = 0xF00
        FPB_NUM_LIT_OFFSET = 8
        fpb_literal_addrs = (FP_CTRL & FPB_NUM_LIT_MASK) >> FPB_NUM_LIT_OFFSET

        # Check whether addr remapping is supported by FPB.
        FP_REMAP_RMPSPT_flag = 0x20000000
        fpb_remap_supported = (FP_REMAP & FP_REMAP_RMPSPT_flag) != 0

        # Number of data watchpoint comparators given by high-order 4 bits of DWT_CTRL.
        DWT_NUM_COMP_MASK = 0xF0000000
        DWT_NUM_COMP_OFFSET = 28
        dwt_num_comparators = (DWT_CTRL & DWT_NUM_COMP_MASK) >> DWT_NUM_COMP_OFFSET

        specs = {}

        # FPB specs
        specs['CPUID'] = CPUID
        specs['FP_CTRL'] = FP_CTRL
        specs['FP_REMAP'] = FP_REMAP
        specs['fpb_version'] = fpb_version
        specs['fpb_remap_supported'] = fpb_remap_supported
        specs['fpb_code_addrs'] = fpb_code_addrs
        # Note: since we're not doing flash-patching, these are not useful to us and do not count
        # toward get_num_hardware_breakpoints.
        specs['fpb_literal_addrs'] = fpb_literal_addrs

        # DWT specs
        specs['DWT_CTRL'] = DWT_CTRL
        specs['dwt_num_comparators'] = dwt_num_comparators

        self.debugger.verboseprint(f'Flashpatch unit version: {fpb_version} '
                                   f'(remap={fpb_remap_supported})')
        self.debugger.verboseprint(f'Flashpatch unit: {fpb_code_addrs} code addrs, '
                                   f'{fpb_literal_addrs} literal comparators')
        self.debugger.verboseprint(f'Data watchpoint/trace unit: {dwt_num_comparators} comparators')

        self.arch_specs = specs  # Cache values. These are constant.

    def get_num_hardware_breakpoints(self):
        if self.arch_specs is None:
            self._get_arch_specs()

        return self.arch_specs['fpb_code_addrs'] + self.arch_specs['dwt_num_comparators']

    def get_num_hardware_breakpoints_used(self):
        if self.arch_specs is None:
            self._get_arch_specs()

        return self._breakpoint_scheduler.get_num_hardware_breakpoints_used()

    def create_hw_breakpoint(self, breakpoint):
        if self.arch_specs is None:
            self._get_arch_specs()

        self._breakpoint_scheduler.schedule_bp(breakpoint)

    def remove_hw_breakpoint(self, breakpoint):
        if self.arch_specs is None:
            self._get_arch_specs()

        self._breakpoint_scheduler.deschedule_bp(breakpoint)

    def sync_hw_breakpoints(self):
        if self.arch_specs is None:
            self._get_arch_specs()

        self._breakpoint_scheduler.sync()

    def breakpoint_scheduler(self):
        return self._breakpoint_scheduler


