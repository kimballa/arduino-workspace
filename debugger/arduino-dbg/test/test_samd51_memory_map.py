# (c) Copyright 2022 Aaron Kimball

import unittest

import arduino_dbg.debugger as dbg
import arduino_dbg.memory_map as memory_map
import arduino_dbg.term as term


class TestArmThumbMemoryMap(unittest.TestCase):
    """
    Set up debugger with SAMD51 architecture, instantiate ArmThumbArchInterface and
    verify memory map properly handles flat address space.
    """

    PLATFORM = 'feather_m4'   # Use ATSAMD51-based platform

    def __init__(self, methodName='runTest'):
        super().__init__(methodName)

    @staticmethod
    def get_debug_config():
        """
        Return configuration settings to use for testing.
        """
        config = {
            'dbg.verbose': False,  # Don't spam terminal with debug output.
            'dbg.colors': False,   # Don't use VT100 colors on output
            'arduino.platform': TestArmThumbMemoryMap.PLATFORM,
        }

        return config


    def setUp(self):
        self.console_printer = term.NullPrinter()
        self.console_printer.start()

        self.debugger = dbg.Debugger(None, None, self.console_printer.print_q, self.PLATFORM,
                                     TestArmThumbMemoryMap.get_debug_config(), is_locked=True)


    def tearDown(self):
        if self.debugger:
            self.debugger.release_cmd_lock()  # Done.
            self.debugger.close()
            self.debugger = None

        if self.console_printer:
            self.console_printer.shutdown()
            self.console_printer = None

    def test_interface_class(self):
        """ Test that correct ArchInterface is set up """
        self.assertEqual(self.debugger.get_conf("arduino.platform"), "feather_m4")
        self.assertEqual(self.debugger.get_conf("arduino.arch"), "samd51x19a")
        self.assertIsNotNone(self.debugger.arch_iface)
        self.assertEqual(self.debugger.arch_iface.__class__.__name__, "ArmThumbArchInterface")

    def test_mem_map_structure(self):
        """ We expect 3 segments (.text, .data, peripherals) in sorted-by-logical-addr order. """
        mmap = self.debugger.arch_iface.memory_map()

        self.assertIsNotNone(mmap)
        self.assertTrue(mmap.validate())
        self.assertEqual(len(mmap.segments), 3)

        self.assertEqual(mmap.segments[0].name, '.text')
        self.assertEqual(mmap.access_mechanism_for_addr(0x100), memory_map.ACCESS_TYPE_RAM)

        self.assertEqual(mmap.segments[1].name, '.data')
        self.assertEqual(mmap.access_mechanism_for_addr(0x20000200), memory_map.ACCESS_TYPE_RAM)

        with self.assertRaises(RuntimeError):
            # Check out-of-bounds addr - this is in Flash-ish memory area in the no-mans-land
            # between .text and the data segment.
            mmap.access_mechanism_for_addr(0x100000)


    def test_text_addressing(self):
        """ Test addressing and access for .text-segment addresses """
        mmap = self.debugger.arch_iface.memory_map()

        # Despite actually residing in Flash, we do not use flash-specific accessors; SAMD51
        # presents it to us as RAM.
        self.assertEqual(mmap.access_mechanism_for_addr(0x100), memory_map.ACCESS_TYPE_RAM)
        self.assertEqual(mmap.logical_to_physical_addr(0x100), 0x100)  # Unchanged

    def test_data_addressing(self):
        """ Test addressing and access for .data-segment addresses """
        mmap = self.debugger.arch_iface.memory_map()

        self.assertEqual(mmap.access_mechanism_for_addr(0x20010000), memory_map.ACCESS_TYPE_RAM)
        self.assertEqual(mmap.logical_to_physical_addr(0x20010000), 0x20010000)  # No change.

        with self.assertRaises(RuntimeError):
            # Check out-of-bounds addr - this is just above the top of the 192 KB of available RAM.
            mmap.access_mechanism_for_addr(0x20030000)


if __name__ == "__main__":
    unittest.main(verbosity=2)

