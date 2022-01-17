#!/usr/bin/env python3
# (c) Copyright 2022 Aaron Kimball

import unittest

import arduino_dbg.stack as stack
import arduino_dbg.symbol as symbol
import arduino_dbg.types as types
from dbg_testcase import *

class TestLocals(DbgTestCase):

    def __init__(self, methodName='runTest'):
        super().__init__(methodName)

    @classmethod
    def getDumpFilename(cls):
        # Dump captured at breakpoint in I2CParallel::getByte()
        return "fixtures/get_byte.dump"

    def test_locals_with_entry_value(self):
        """
        Test retrieving local var values with DW_OP_entry_value.
        """
        # Use call frame #2 in saved stack for get_byte.dump:
        # 2. 193c: I2C4BitNhdByteSender::readByte(unsigned char, unsigned char)
        #     (I2C4BitNhdByteSender.cpp:74)

        # pre-calculate and unwind frames.
        frames = self.debugger.get_backtrace(limit=3)
        self.assertTrue(len(frames) >= 3)
        frame = frames[2]
        self.assertIsInstance(frame, stack.CallFrame)

        frame_regs = self.debugger.get_frame_regs(2)
        self.assertIsInstance(frame_regs, dict)

        # Get the MethodInfo and LexicalScope entries surrounding $PC.
        frame_scopes = self.debugger.get_frame_vars(2)
        var_values = {}
        for scope in frame_scopes:
            for formal in scope.getFormals():
                val = formal.getValue(frame_regs, frame)
                if formal.name is not None and val is not None:
                    var_values[formal.name] = val

            for (varname, variable) in scope.getVariables():
                val = variable.getValue(frame_regs, frame)
                if variable.name is not None and val is not None:
                    var_values[variable.name] = val

        # We expect to produce values for: ctrlFlags, enFlag, send, __c
        # Note that values for ctrlFlags & enFlag are unreliable due to call-clobbered regs.
        # We are currently unable to access values for: scan, v, this
        self.assertEqual(len(var_values), 4)
        self.assertEqual(var_values['send'], 191) # I believe this is a reliable local to test.


if __name__ == "__main__":
    unittest.main(verbosity=2)
