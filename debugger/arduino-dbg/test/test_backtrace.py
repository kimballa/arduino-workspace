#!/usr/bin/env python3
# (c) Copyright 2022 Aaron Kimball

import unittest

import arduino_dbg.debugger as dbg
import arduino_dbg.stack as stack
import arduino_dbg.symbol as symbol
from dbg_testcase import DbgTestCase


class TestBacktrace(DbgTestCase):

    def __init__(self, methodName='runTest'):
        super().__init__(methodName)

    @classmethod
    def getDumpFilename(cls):
        # Dump captured at breakpoint in I2CParallel::getByte()
        return "fixtures/get_byte.dump"

    def setUp(self):
        self.debugger.clear_frame_cache()  # Clear backtraces from prior testcases.
        self.debugger.set_conf('dbg.internal.stack.frames', True)  # Reset this conf
        self.debugger.set_conf('dbg.backtrace.limit', dbg._DEFAULT_MAX_BACKTRACE_DEPTH)

    def test_backtrace_size(self):
        """ Test that we can see all the methods we expect to """
        frames = self.debugger.get_backtrace()
        self.assertIsInstance(frames, list)
        self.assertEqual(len(frames), 7)  # We expect 7 backtrace frames

    def test_uncapped_backtrace_hits_config_limit(self):
        """ Test that uncapped backtrace aborts early if it hits dbg.backtrace.limit """
        self.debugger.set_conf('dbg.backtrace.limit', 4)
        frames = self.debugger.get_backtrace()
        self.assertIsInstance(frames, list)
        # We expect 4 backtrace frames (not 7) b/c we hit the limit
        self.assertEqual(len(frames), 4)

    def test_capped_backtrace_hits_config_limit(self):
        """ Test that capped backtrace aborts early if it hits dbg.backtrace.limit """
        self.debugger.set_conf('dbg.backtrace.limit', 4)
        frames = self.debugger.get_backtrace(5)  # Specify our own limit, greater than cap.
        self.assertIsInstance(frames, list)
        # We expect 4 backtrace frames (not 5) b/c we hit the limit
        self.assertEqual(len(frames), 4)

    def test_backtrace_incremental(self):
        """ Test that multiple backtraces with increasing limits incrementally reveal the stack. """
        frames = self.debugger.get_backtrace(2)
        self.assertIsInstance(frames, list)
        self.assertEqual(len(frames), 2)  # We expect 2 so far.
        frames = self.debugger.get_backtrace(4)
        self.assertEqual(len(frames), 4)  # ... and now four
        frames = self.debugger.get_backtrace()  # Get the rest.
        self.assertEqual(len(frames), 7)  # We expect 7 backtrace frames

    def test_hiding_frames(self):
        """ Test that we can gracefully hide service frames from the user """
        try:
            # initial state: show service frames enabled
            frames = self.debugger.get_backtrace(2)
            self.assertEqual(len(frames), 2)  # We expect 2 so far.
            self.assertEqual(frames[0].name, '__dbg_service')

            self.debugger.set_conf('dbg.internal.stack.frames', False)
            frames = self.debugger.get_backtrace(2)  # Reprocess. Will need to grab 3 total frames.
            self.assertEqual(len(frames), 2)  # But we expect only 2 response frames.
            self.assertEqual(frames[0].demangled, 'I2CParallel::getByte()')  # 1st user method!

            frames = self.debugger.get_backtrace()  # Get all user frames.
            self.assertEqual(len(frames), 6)  # We expect 6 user frames.

            self.debugger.set_conf('dbg.internal.stack.frames', True)
            frames = self.debugger.get_backtrace()  # Get all frames.
            self.assertEqual(len(frames), 7)  # We expect 7 total frames.

            self.debugger.set_conf('dbg.internal.stack.frames', False)
            frames = self.debugger.get_backtrace()  # Get all frames.
            self.assertEqual(len(frames), 6)  # ... now back to just 6 frames.

            frames = self.debugger.get_backtrace(force_unhide=True)  # Override conf.
            self.assertEqual(len(frames), 7)  # We expect 7 total frames.
        finally:
            self.debugger.set_conf('dbg.internal.stack.frames', True)  # Reset this conf.

    def test_backtrace_incremental_2(self):
        """ Test that a limit equal to the true stack depth reveals the whole stack """
        frames = self.debugger.get_backtrace(2)
        self.assertIsInstance(frames, list)
        self.assertEqual(len(frames), 2)  # We expect 2 so far.
        frames = self.debugger.get_backtrace(7)  # Get the rest.
        self.assertEqual(len(frames), 7)  # We expect 7 backtrace frames

    def test_backtrace_frame(self):
        """ Test that frames in the backtrace have correct information populated. """
        frames = self.debugger.get_backtrace()
        frame = frames[1]  # I2CParallel::getByte()

        self.assertIsInstance(frame, stack.CallFrame)
        self.assertEqual(frame.addr, 0x18a2)
        self.assertEqual(frame.demangled, 'I2CParallel::getByte()')
        self.assertEqual(frame.source_line, 'I2CParallel.cpp:50')

    def test_backtrace_frame_limit(self):
        """ Test that frames are correctly populated when we use a limit on bt retrieval """
        frames = self.debugger.get_backtrace(2)  # Just get two frames.
        frame = frames[1]  # I2CParallel::getByte()

        self.assertIsInstance(frame, stack.CallFrame)
        self.assertEqual(frame.addr, 0x18a2)
        self.assertEqual(frame.demangled, 'I2CParallel::getByte()')
        self.assertEqual(frame.source_line, 'I2CParallel.cpp:50')

    def test_inline_chain(self):
        """ Test that we detect our position within an inline method in a frame """
        frames = self.debugger.get_backtrace()
        frame = frames[6]  # method is main(); inside inlined `loop()` within `main()`.

        self.assertIsInstance(frame, stack.CallFrame)
        self.assertEqual(frame.addr, 0x23f4)
        self.assertEqual(frame.demangled, 'main')
        self.assertEqual(len(frame.demangled_inline_chain), 4)
        self.assertEqual(len(frame.inline_chain), 4)
        self.assertEqual(frame.demangled_inline_chain, [
            'size_t Print::write()',
            'size_t Print::print()',
            'void loop()',
            'main'])

    def test_method_type_in_backtrace(self):
        """ Test that method signatures are correctly associated with backtrace frames """
        frames = self.debugger.get_backtrace()
        frame = frames[6]  # main()

        # Check that the symbol info is resolved correctly.
        self.assertIsInstance(frame.sym, symbol.Symbol)
        self.assertEqual(frame.sym.name, 'main')
        self.assertEqual(frame.sym.demangled, 'main')
        self.assertEqual(frame.sym.size, 1210)
        self.assertEqual(frame.sym.addr, 0x202e)

    def test_frame_unwinds_equivalent_for_method(self):
        """ Test that CFI and prologue analyzer agree on a normal method """
        frames = self.debugger.get_backtrace()
        regs = self.debugger.get_registers()

        frame = frames[0]  # __dbg_service()

        prologue_sz = self.debugger.arch_iface.stack_frame_size_for_prologue(frame.addr, frame.sym)
        cfi_record_sz = self.debugger.arch_iface.stack_frame_size_by_cfi(frame, regs)

        self.assertEqual(prologue_sz, cfi_record_sz)

    def test_frame_unwinds_equivalent_for_ISR(self):
        """ Test that CFI and prologue analyzer agree on an ISR """
        frames = self.debugger.get_backtrace()

        pre_frame = frames[0]  # __dbg_service()
        regs = pre_frame.unwound_registers
        frame = frames[1]  # TIMER1_COMPA_vect()

        prologue_sz = self.debugger.arch_iface.stack_frame_size_for_prologue(frame.addr, frame.sym)
        cfi_record_sz = self.debugger.arch_iface.stack_frame_size_by_cfi(frame, regs)

        self.assertEqual(prologue_sz, cfi_record_sz)

    # TODO(aaron): Need to test equivalent frame unwind agreement for a method that
    # involves the $SP SUBI state machine in AVR.


if __name__ == "__main__":
    unittest.main(verbosity=2)
