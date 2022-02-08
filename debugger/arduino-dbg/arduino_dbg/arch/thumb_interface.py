# (c) Copyright 2022 Aaron Kimball

"""
ARM Thumb-specific architecture interface.
"""

import arduino_dbg.arch as arch
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

        # Flash for .text starts at address 0 but is mem-mapped on-device to use the same access
        # as you would for ordinary SRAM. No Flash-specific accessors required.
        self._mem_map.add_segment(mmap.Segment('.text', mmap.MEM_FLASH, mmap.ACCESS_TYPE_RAM,
                                               logical_code_min, physical_code_min, code_size))

        # .data and .bss start at 0x20000000  and run for RAMSIZE bytes up from there.
        self._mem_map.add_segment(mmap.Segment('.data', mmap.MEM_RAM, mmap.ACCESS_TYPE_RAM,
                                               logical_data_min, physical_data_min, data_size))

        self._mem_map.validate()
        return self._mem_map

    def true_pc(self, reg_pc):
        # ARM: low-order bit of 32-bit $PC is the arm/thumb state; should be
        # held to zero for true instruction pointer address.
        return reg_pc & ~0x1

    def mem_to_pc(self, mem_pc):
        return self.true_pc(mem_pc)


