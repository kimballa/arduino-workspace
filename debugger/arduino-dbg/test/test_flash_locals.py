#!/usr/bin/env python3
# (c) Copyright 2022 Aaron Kimball

import unittest

import arduino_dbg.stack as stack
import arduino_dbg.eval_location as el
from dbg_testcase import DbgTestCase


class TestFlashLocals(DbgTestCase):

    def __init__(self, methodName='runTest'):
        super().__init__(methodName)

    @classmethod
    def getDumpFilename(cls):
        return "fixtures/read_byte.dump"

    def test_flash_string(self):
        """
        Test retrieving a local var with type 'const char[]' that is in the .text
        segment -- needs to be retrieved from Flash and formatted as a null-terminated string.
        """
        # Use call frame #1 in saved stack for read_byte.dump:
        # 1. 194e: I2C4BitNhdByteSender::readByte(unsigned char, unsigned char)
        #     (I2C4BitNhdByteSender.cpp:75)

        # pre-calculate and unwind frames.
        frames = self.debugger.get_backtrace(limit=2)
        self.assertTrue(len(frames) >= 2)
        frame = frames[1]
        self.assertIsInstance(frame, stack.CallFrame)

        frame_regs = self.debugger.get_frame_regs(1)
        self.assertIsInstance(frame_regs, dict)

        # Get the MethodInfo and LexicalScope entries surrounding $PC.
        frame_scopes = self.debugger.get_frame_vars(1)
        var_values = {}
        for scope in frame_scopes:
            for formal in scope.getFormals():
                val, flags = formal.getValue(frame_regs, frame)
                if formal.name is not None and val is not None:
                    self.assertFalse(el.LookupFlags.has_errors(flags))
                    var_values[formal.name] = val

            for (varname, variable) in scope.getVariables():
                val, flags = variable.getValue(frame_regs, frame)
                if variable.name is not None and val is not None:
                    self.assertFalse(el.LookupFlags.has_errors(flags))
                    if variable.name == "__c":
                        # Prove we decoded this from flash.
                        self.assertTrue(flags & el.LookupFlags.FLASH_ADDR)
                    var_values[variable.name] = val

        # Assert that we correctly processed the data as a string.
        self.assertEqual(var_values['__c'], "I2C4BitNhdByteSender.cpp")


if __name__ == "__main__":
    unittest.main(verbosity=2)
