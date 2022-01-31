#!/usr/bin/env python3
# (c) Copyright 2022 Aaron Kimball

import unittest

import arduino_dbg.stack as stack
import arduino_dbg.eval_location as el
from dbg_testcase import DbgTestCase


class TestCharPtr(DbgTestCase):

    def __init__(self, methodName='runTest'):
        super().__init__(methodName)

    @classmethod
    def getDumpFilename(cls):
        return "fixtures/print_msg.dump"

    def test_char_ptr(self):
        """
        Test reading a local var which is `const char*`.
        Retrieve the address held by the variable itself as well as the display the
        variable-length string it points to in RAM.
        """
        # Use call frame #1 in saved stack for print_msg.dump:
        # 1. 2390: main  (poetrybot.cpp:84)
        #     Inlined method calls: void printMsg() in void loop() in main

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
                    var_values[variable.name] = val

        # Assert that we correctly processed the data as a pointer to a string (const char*).
        # The result is a 2-tuple: #0 is the address in RAM where the pointer points,
        # and #1 is the string itself, read fully despite no static knowledge of the length of
        # the pointed-to char array. (The debugger should stop at the null terminator.)
        self.assertEqual(var_values['msg'], (0x14C, "This is a message from mission control."))


if __name__ == "__main__":
    unittest.main(verbosity=2)
