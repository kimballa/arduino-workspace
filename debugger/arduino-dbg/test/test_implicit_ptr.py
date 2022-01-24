#!/usr/bin/env python3
# (c) Copyright 2022 Aaron Kimball

import unittest

import arduino_dbg.stack as stack
import arduino_dbg.symbol as symbol
import arduino_dbg.eval_location as el
import arduino_dbg.types as types
from dbg_testcase import *

class TestImplicitPtr(DbgTestCase):

    def __init__(self, methodName='runTest'):
        super().__init__(methodName)

    @classmethod
    def getDumpFilename(cls):
        return "fixtures/startup.dump"

    def test_implicit_ptr(self):
        """
        Test reading a local `const char*` which is optimized away to an implicit ptr.

        Verify that the "address" is reduced to an impicit pointer, but it can be
        "dereferenced" by the debugger to the appropriate string.
        """
        # Use call frame #1 in saved stack for startup.dump:
        # 1. 222a: main  (dbg.cpp:365)
        #    Inlined method calls: void __dbg_trace() in void __user_setup() in void setup() in main

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

        # Assert that we correctly processed the data as an implicit pointer to a string (const char*).
        # The result is a 2-tuple: #0 is the implicit pointer stand-in,
        # and #1 is the string itself, read fully despite no actual RAM address to retrieve it from;
        # the value was hallucinated from a DwarfProcedure in the .debug_info section.
        funcOrFile = var_values['funcOrFile']
        self.assertEqual(len(funcOrFile), 2) # 2-tuple.
        implicit_ptr = funcOrFile[0]
        string_data = funcOrFile[1]
        self.assertTrue(isinstance(implicit_ptr, el.ImplicitPtr))
        self.assertEqual(string_data, 'void __user_setup()')


if __name__ == "__main__":
    unittest.main(verbosity=2)
