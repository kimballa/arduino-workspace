#!/usr/bin/env python3
# (c) Copyright 2022 Aaron Kimball

import unittest

import arduino_dbg.breakpoint as breakpoint
from dbg_testcase import DbgTestCase
# Import of mock auto-injects it into factory dictionary.
import mock.mock_thumb  # noqa: F401


class TestHardwareBreakpoints(DbgTestCase):
    """
    Test 'breakpoint' module as interacts with (mock) ARM SAMD51 device.
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

    def test_bp_counts(self):
        # 2 fpb + 2 dwt = 4
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints(), 4)
        self.assertEqual(self.debugger.arch_iface.get_num_hardware_breakpoints_used(), 0)


    def test_one_bp(self):
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
        self.assertEqual(self.debugger.arch_iface._breakpoint_scheduler.fpb_comparators[0], bp)



if __name__ == "__main__":
    unittest.main(verbosity=2)
