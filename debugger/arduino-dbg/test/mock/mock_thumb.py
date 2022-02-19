# (c) Copyright 2022 Aaron Kimball

"""
Subclasses of ArmThumbArchInterface, etc. for unit testing purposes.
"""

import arduino_dbg.arch as arch
import arduino_dbg.arch.thumb_interface as thumb_interface


class MockThumbInterface(thumb_interface.ArmThumbArchInterface):
    """
    Injectible ArmThumbArchInterface. Accepts preconfigured 'arch_specs' with
    definitions for:
        * fpb_version (1 or 2)
        * fpb_remap_supported (Bool)
        * fpb_code_addrs (nr of hw bp slots)
        * fpb_literal_addrs (unused)
        * dwt_num_comparators (nr of hw bp slots)

    """

    def __init__(self, debugger):
        super().__init__(debugger)

        self.arch_specs = {}

        # Superclass will set up a CortexBreakpointScheduler; override it here.
        self._breakpoint_scheduler = MockCortexBreakpointScheduler(self)

    def parse_arch_specs(self, arch_specs_strs):
        """
        In the local context arch_specs_strs will be an empty list. Our
        arch_specs is set up based on preconfigured data.
        """
        pass

    def provide_arch_specs(self, new_arch_specs):
        """
        Override arch_specs with the provided mapping.
        """
        self.arch_specs = new_arch_specs.copy()
        self._breakpoint_scheduler.loaded_params = False  # Force bp scheduler to reset internal state.


class MockCortexBreakpointScheduler(thumb_interface.CortexBreakpointScheduler):
    """
    Use same scheduling logic as CortexBreakpointScheduler but don't actually
    send traffic to device.
    """

    def _program_fpb_breakpoint(self, is_enable, reg_id, pc_addr):
        pass  # Don't actually POKE any registers/memory.

    def _program_dwt_breakpoint(self, is_enable, reg_id, pc_addr):
        pass  # Don't actually POKE any registers/memory.


# Loading the mock_thumb module auto-injects MockThumbInterface over ArmThumbArchInterface.
arch.inject_arch_interface('ArmThumbArchInterface', MockThumbInterface)

