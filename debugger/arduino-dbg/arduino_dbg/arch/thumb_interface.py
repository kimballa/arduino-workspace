# (c) Copyright 2022 Aaron Kimball

"""
ARM Thumb-specific architecture interface.
"""

import arduino_dbg.arch as arch


@arch.iface
class ArmThumbArchInterface(arch.ArchInterface):
    """
    ARM Thumb-specific implementation of ArchInterface.
    """

    def __init__(self, debugger):
        super().__init__(debugger)

        # Thumb is 32-bit machine word size.
        assert debugger.get_arch_conf('int_size') == 4

    def true_pc(self, reg_pc):
        # ARM: low-order bit of 32-bit $PC is the arm/thumb state; should be
        # held to zero for true instruction pointer address.
        return reg_pc & ~0x1

    def mem_to_pc(self, mem_pc):
        return self.true_pc(mem_pc)


