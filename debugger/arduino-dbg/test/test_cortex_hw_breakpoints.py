#!/usr/bin/env python3
# (c) Copyright 2022 Aaron Kimball

import unittest

import arduino_dbg.arch as arch
import arduino_dbg.arch.thumb_interface as thumb_interface
import arduino_dbg.breakpoint as breakpoint
from dbg_testcase import DbgTestCase
# Import of mock auto-injects it into factory dictionary.
import mock.mock_thumb  # noqa: F401


class TestCortexHardwareBreakpoints(DbgTestCase):
    """
    Test 'breakpoint' module as interacts with (mock) ARM SAMD51 / Cortex M-series device.

    This has tests specific to ArmThumbArchInterface and CortexBreakpointScheduler as well as some
    tests of basic Breakpoint / BreakpointDatabase capabilities.
    """

    def __init__(self, methodName='runTest'):
        super().__init__(methodName)

    @classmethod
    def getDumpFilename(cls):
        # Dump captured in empty.elf
        return "fixtures/cortex-m4-img.dump"

    @classmethod
    def getArchSpecs(cls):
        # Set up a reasonable arch_specs for testing.
        specs = {}
        specs['fpb_version'] = 1
        specs['fpb_remap_supported'] = True
        specs['fpb_code_addrs'] = 2
        specs['fpb_literal_addrs'] = 0
        specs['dwt_num_comparators'] = 2

        return specs

    def setUp(self):
        self.debugger.clear_frame_cache()  # Clear backtraces from prior testcases.
        # Reset arch_specs configuration
        # Assumes that arch_iface is a MockThumbInterface.
        self.debugger.arch_iface.provide_arch_specs(self.getArchSpecs())

        # Clear breakpoint db.
        self.breakpoint_db = self.debugger.breakpoints()
        self.breakpoint_db.reset()

    def test_iface_types(self):
        """ Test that the arch interface objects have the expected types. """
        self.assertIsInstance(self.debugger.arch_iface, thumb_interface.ArmThumbArchInterface)
        self.assertIsInstance(self.debugger.arch_iface.breakpoint_scheduler(),
                              thumb_interface.CortexBreakpointScheduler)


    def test_bp_counts(self):
        """ Test the expected number of available hw breakpoints. """
        # 2 fpb + 2 dwt = 4
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints(), 4)
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)


    def test_one_bp(self):
        """ Creating a breakpoint adds it to the FPB list. """
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)

        addr = 0x4000
        sig = breakpoint.Breakpoint.make_hw_signature(addr)
        bp = self.breakpoint_db.register_bp(addr, sig, True)
        self.assertIsNotNone(bp)
        self.assertEqual(bp.pc, addr)
        self.assertFalse(bp.enabled)  # bp defined but not installed.
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)  # Still 0.

        bp.enable()
        self.assertTrue(bp.enabled)
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 1)

        # First breakpoint should go in the FPB.
        self.assertTrue(bp in self.debugger.arch_iface.breakpoint_scheduler().fpb_comparators)


    def test_multi_bp(self):
        """ Multiple breakpoints should be enqueued in the FPB list. """

        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)

        addr1 = 0x4000
        sig1 = breakpoint.Breakpoint.make_hw_signature(addr1)
        bp1 = self.breakpoint_db.register_bp(addr1, sig1, True)
        bp1.enable()
        self.assertTrue(bp1.enabled)
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 1)

        addr2 = 0x5500
        sig2 = breakpoint.Breakpoint.make_hw_signature(addr2)
        bp2 = self.breakpoint_db.register_bp(addr2, sig2, True)
        bp2.enable()
        self.assertTrue(bp2.enabled)
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 2)

        # Both breakpoints should be in the FPB.
        self.assertTrue(bp1 in self.debugger.arch_iface.breakpoint_scheduler().fpb_comparators)
        self.assertTrue(bp2 in self.debugger.arch_iface.breakpoint_scheduler().fpb_comparators)

    def test_dwt_spill(self):
        """ Once we run out of FPB breakpoints, spill them to the DWT. """

        specs = self.getArchSpecs()
        specs['fpb_code_addrs'] = 1  # A 2nd BP will need to spill to DWT.
        self.debugger.arch_iface.provide_arch_specs(specs)  # Use this override config.

        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints(), 3)  # 1 FPB + 2 DWT
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)

        addr1 = 0x4000
        sig1 = breakpoint.Breakpoint.make_hw_signature(addr1)
        bp1 = self.breakpoint_db.register_bp(addr1, sig1, True)
        bp1.enable()
        self.assertTrue(bp1.enabled)
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 1)

        addr2 = 0x5500
        sig2 = breakpoint.Breakpoint.make_hw_signature(addr2)
        bp2 = self.breakpoint_db.register_bp(addr2, sig2, True)
        bp2.enable()
        self.assertTrue(bp2.enabled)
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 2)

        # Both breakpoints should be in the FPB.
        self.assertTrue(bp1 in self.debugger.arch_iface.breakpoint_scheduler().fpb_comparators)
        self.assertTrue(bp2 in self.debugger.arch_iface.breakpoint_scheduler().dwt_comparators)

    def test_bp_exhaustion(self):
        """ Test graceful decline if all HW breakpoints are in use. """

        specs = self.getArchSpecs()
        specs['fpb_code_addrs'] = 1  # Only one BP available.
        specs['dwt_num_comparators'] = 0
        self.debugger.arch_iface.provide_arch_specs(specs)  # Use this override config.

        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints(), 1)  # 1 FPB
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)

        addr1 = 0x4000
        sig1 = breakpoint.Breakpoint.make_hw_signature(addr1)
        bp1 = self.breakpoint_db.register_bp(addr1, sig1, True)
        bp1.enable()
        self.assertTrue(bp1.enabled)
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 1)

        addr2 = 0x5500
        sig2 = breakpoint.Breakpoint.make_hw_signature(addr2)
        bp2 = self.breakpoint_db.register_bp(addr2, sig2, True)  # Should be OK to this point.
        with self.assertRaises(arch.HWBreakpointsFullError):
            bp2.enable()  # Should raise HWBreakpointsFullError.

        # First breakpoint should be in the FPB.
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 1)
        self.assertTrue(bp1 in self.debugger.arch_iface.breakpoint_scheduler().fpb_comparators)

        # 2nd bp shouldn't be active.
        self.assertFalse(bp2.enabled)
        self.assertFalse(bp2 in self.debugger.arch_iface.breakpoint_scheduler().fpb_comparators)
        self.assertFalse(bp2 in self.debugger.arch_iface.breakpoint_scheduler().dwt_comparators)


    def test_fpb_v1_sram_pc_to_dwt(self):
        """
        On FPB rev 1, SRAM-based $PC needs to be scheduled in DWT.

        FPB rev 2 has 32-bit $PC identifier but FPB v1 cannot trap .code-based $PC values; only
        the DWT can do this.
        """
        specs = self.getArchSpecs()
        self.debugger.arch_iface.provide_arch_specs(specs)

        self.assertEqual(specs['fpb_version'], 1)  # Virtual FPB is v1 by default.

        addr = 0x20004000  # Pick SRAM-based addr.
        sig = breakpoint.Breakpoint.make_hw_signature(addr)
        bp = self.breakpoint_db.register_bp(addr, sig, True)
        self.assertIsNotNone(bp)
        self.assertEqual(bp.pc, addr)
        self.assertFalse(bp.enabled)  # bp defined but not installed.
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)  # Still 0.

        bp.enable()
        self.assertTrue(bp.enabled)
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 1)

        # First breakpoint should go in the DWT, not FPB this time..
        self.assertFalse(bp in self.debugger.arch_iface.breakpoint_scheduler().fpb_comparators)
        self.assertTrue(bp in self.debugger.arch_iface.breakpoint_scheduler().dwt_comparators)


    def test_fpb_v2_sram_pc_to_dwt(self):
        """ On FPB rev 2, it can also trap SRAM-based $PC. """
        specs = self.getArchSpecs()
        specs['fpb_version'] = 2  # Override FPB revision.
        self.debugger.arch_iface.provide_arch_specs(specs)

        self.assertEqual(specs['fpb_version'], 2)  # Override virtual FPB to be v2

        addr = 0x20004000  # Pick SRAM-based addr.
        sig = breakpoint.Breakpoint.make_hw_signature(addr)
        bp = self.breakpoint_db.register_bp(addr, sig, True)
        self.assertIsNotNone(bp)
        self.assertEqual(bp.pc, addr)
        self.assertFalse(bp.enabled)  # bp defined but not installed.
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)  # Still 0.

        bp.enable()
        self.assertTrue(bp.enabled)
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 1)

        # First breakpoint should remain FPB-scheduled.
        self.assertTrue(bp in self.debugger.arch_iface.breakpoint_scheduler().fpb_comparators)
        self.assertFalse(bp in self.debugger.arch_iface.breakpoint_scheduler().dwt_comparators)


    def test_double_enable(self):
        """ Enabling a BP is an idempotent operation. """

        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)

        addr = 0x4000
        sig = breakpoint.Breakpoint.make_hw_signature(addr)
        bp = self.breakpoint_db.register_bp(addr, sig, True)
        self.assertIsNotNone(bp)
        self.assertEqual(bp.pc, addr)
        self.assertFalse(bp.enabled)  # bp defined but not installed.
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)  # Still 0.

        bp.enable()
        self.assertTrue(bp.enabled)
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 1)
        self.assertTrue(bp in self.debugger.arch_iface.breakpoint_scheduler().fpb_comparators)

        # Try it twice.
        bp.enable()  # Should return silently w/o doing anything.
        self.assertTrue(bp.enabled)
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 1)
        self.assertTrue(bp in self.debugger.arch_iface.breakpoint_scheduler().fpb_comparators)
        # Don't fill a 2nd slot with the same bp.
        self.assertIsNone(self.debugger.arch_iface.breakpoint_scheduler().fpb_comparators[1])

    def test_redundant_enable(self):
        """ Enabling 2 BP's at one addr causes one to fail. """

        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)

        addr = 0x4000
        sig1 = breakpoint.Breakpoint.make_hw_signature(addr)
        bp1 = self.breakpoint_db.register_bp(addr, sig1, True)
        bp1.enable()
        self.assertTrue(bp1.enabled)
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 1)

        # The breakpoint database itself is too smart to allow this...
        sig2 = breakpoint.Breakpoint.make_hw_signature(addr)  # Same addr as above.
        bp2 = self.breakpoint_db.register_bp(addr, sig2, True)
        self.assertTrue(bp1 is bp2)  # register_bp() just returns existing entry.

        # But we can always roll our own explicitly.
        bp3 = breakpoint.Breakpoint(self.debugger, addr, sig2, is_dynamic=True)
        self.assertFalse(bp1 is bp3)  # slip a new breakpoint by.
        self.assertTrue(bp2.enabled)
        bp2.enable()  # Nothing happens.
        self.assertTrue(bp2.enabled)

        with self.assertRaises(arch.BreakpointAddrExistsError):
            bp3.enable()  # Complains
        self.assertFalse(bp3.enabled)
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 1)  # Still 1

        # Only first breakpoint should be in the FPB.
        self.assertTrue(bp1 in self.debugger.arch_iface.breakpoint_scheduler().fpb_comparators)
        self.assertFalse(bp3 in self.debugger.arch_iface.breakpoint_scheduler().fpb_comparators)

    def test_multi_register_same_bp(self):
        """ Multiple bp registrations of the same addr return the same Breakpoint """

        addr = 0x4000
        sig1 = breakpoint.Breakpoint.make_hw_signature(addr)
        bp1 = self.breakpoint_db.register_bp(addr, sig1, True)
        bp1.enable()
        self.assertTrue(bp1.enabled)
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 1)

        # The breakpoint database itself is too smart to allow this...
        sig2 = breakpoint.Breakpoint.make_hw_signature(addr)  # Same addr as above.
        bp2 = self.breakpoint_db.register_bp(addr, sig2, True)
        self.assertTrue(bp1 is bp2)  # register_bp() just returns existing entry.

    def test_enable_disable(self):
        """ We can enable and then disable a breakpoint. """

        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)

        addr = 0x4000
        sig = breakpoint.Breakpoint.make_hw_signature(addr)
        bp = self.breakpoint_db.register_bp(addr, sig, True)
        self.assertIsNotNone(bp)
        self.assertEqual(bp.pc, addr)
        self.assertFalse(bp.enabled)  # bp defined but not installed.
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)  # Still 0.

        bp.enable()
        self.assertTrue(bp.enabled)
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 1)
        self.assertTrue(bp in self.debugger.arch_iface.breakpoint_scheduler().fpb_comparators)

        bp.disable()
        self.assertFalse(bp.enabled)
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)
        self.assertFalse(bp in self.debugger.arch_iface.breakpoint_scheduler().fpb_comparators)

    def test_redundant_disable(self):
        """ Disabling a breakpoint can only happen if its enabled. """
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)

        addr = 0x4000
        sig = breakpoint.Breakpoint.make_hw_signature(addr)
        bp = self.breakpoint_db.register_bp(addr, sig, True)
        self.assertIsNotNone(bp)
        self.assertEqual(bp.pc, addr)
        self.assertFalse(bp.enabled)  # bp defined but not installed.
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)  # Still 0.

        bp.enable()
        self.assertTrue(bp.enabled)
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 1)
        self.assertTrue(bp in self.debugger.arch_iface.breakpoint_scheduler().fpb_comparators)

        bp.disable()
        self.assertFalse(bp.enabled)
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)
        self.assertFalse(bp in self.debugger.arch_iface.breakpoint_scheduler().fpb_comparators)

        # Run it a second time.
        with self.assertRaises(arch.BreakpointNotEnabledError):
            bp.disable()  # Expect complaint.

        self.assertFalse(bp.enabled)
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)
        self.assertFalse(bp in self.debugger.arch_iface.breakpoint_scheduler().fpb_comparators)

    def test_disable_phantom_bp(self):
        """ Disabling a breakpoint that isn't "real" raises BreakpointNotEnabledErr """

        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)

        addr = 0x4000
        sig = breakpoint.Breakpoint.make_hw_signature(addr)
        # Make a bp 'raw'; don't register it or enable it.
        bp = breakpoint.Breakpoint(self.debugger, addr, sig, is_dynamic=True)
        self.assertIsNotNone(bp)
        self.assertEqual(bp.pc, addr)
        self.assertFalse(bp.enabled)  # bp defined but not installed.
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)  # Still 0.

        with self.assertRaises(arch.BreakpointNotEnabledError):
            bp.disable()  # Expect complaint.


    def test_delete_bp_also_disables(self):
        """ Deleting a breakpoint will disable it. """

        addr = 0x4000
        sig = breakpoint.Breakpoint.make_hw_signature(addr)
        bp = self.breakpoint_db.register_bp(addr, sig, True)
        self.assertIsNotNone(bp)
        self.assertEqual(bp.pc, addr)
        self.assertFalse(bp.enabled)  # bp defined but not installed.
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)  # Still 0.

        bp.enable()
        self.assertTrue(bp.enabled)
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 1)
        self.assertTrue(bp in self.debugger.arch_iface.breakpoint_scheduler().fpb_comparators)

        self.assertTrue(bp in self.breakpoint_db.breakpoints())
        self.assertEqual(bp, self.breakpoint_db.breakpoints()[0])

        self.breakpoint_db.delete(0)  # Delete first/only breakpoint.

        self.assertFalse(bp.enabled)  # bp is now disabled.
        # ... removed from Cortex bp scheduler
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)
        self.assertFalse(bp in self.debugger.arch_iface.breakpoint_scheduler().fpb_comparators)
        # ... and removed from breakpoint db.
        self.assertFalse(bp in self.breakpoint_db.breakpoints())


    def test_enable_after_disable(self):
        """ The sequence enable > disable > enable should succeed. """

        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)

        addr = 0x4000
        sig = breakpoint.Breakpoint.make_hw_signature(addr)
        bp = self.breakpoint_db.register_bp(addr, sig, True)
        self.assertIsNotNone(bp)
        self.assertEqual(bp.pc, addr)
        self.assertFalse(bp.enabled)  # bp defined but not installed.
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)  # Still 0.

        bp.enable()
        self.assertTrue(bp.enabled)
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 1)
        self.assertTrue(bp in self.debugger.arch_iface.breakpoint_scheduler().fpb_comparators)

        bp.disable()
        self.assertFalse(bp.enabled)
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)
        self.assertFalse(bp in self.debugger.arch_iface.breakpoint_scheduler().fpb_comparators)

        # After we disable a breakpoint, we can enable it all over again.
        bp.enable()
        self.assertTrue(bp.enabled)
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 1)
        self.assertTrue(bp in self.debugger.arch_iface.breakpoint_scheduler().fpb_comparators)


if __name__ == "__main__":
    unittest.main(verbosity=2)
