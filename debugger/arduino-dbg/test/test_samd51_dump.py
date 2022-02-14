#!/usr/bin/env python3
# (c) Copyright 2022 Aaron Kimball

import unittest

from dbg_testcase import DbgTestCase


class TestSamd51Dump(DbgTestCase):

    def __init__(self, methodName='runTest'):
        super().__init__(methodName)

    @classmethod
    def getDumpFilename(cls):
        # Dump captured in empty.elf
        return "fixtures/cortex-m4-img.dump"

    def setUp(self):
        self.debugger.clear_frame_cache()  # Clear backtraces from prior testcases.

    def test_backtrace_size(self):
        frames = self.debugger.get_backtrace()
        self.assertIsInstance(frames, list)
        self.assertEqual(len(frames), 7)  # We expect 7 backtrace frames

    def test_get_ram_val(self):
        # 1 byte data at 0x2000011c should have value '8'.
        addr = 0x2000011c
        expected = 8
        mem_val = self.debugger.get_sram(addr, 1)
        self.assertEqual(mem_val, expected)



if __name__ == "__main__":
    unittest.main(verbosity=2)
