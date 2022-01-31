# (c) Copyright 2022 Aaron Kimball

import arduino_dbg.dump as dump
import arduino_dbg.term as term

import unittest


class DbgTestCase(unittest.TestCase):
    """
    TestCase subclass that loads a core dump and ELF into a local Debugger
    session as a fixture.

    You must implement getDumpFilename() as a @classmethod to specify the
    dump file to load.
    - This filename should be relative to this 'test' directory, which is the cwd for the test.
    - If this dump loads an ELF file, the elf_file_name parameter in the dump file should be
      relative to the location of the dump file.
    """

    console_printer = None
    debugger = None
    dbg_service = None

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
        }

        return config


    @classmethod
    def get_debugger(cls):
        """
        Return the initialized Debugger test fixture (with dump file loaded).
        """
        return cls.debugger

    @classmethod
    def getDumpFilename(cls):
        """
        Return the filename of the test fixture image.
        """
        raise Exception("You must implement @classmethod getDumpFilename() to specify image to load")

    @classmethod
    def setUpClass(cls):
        filename = cls.getDumpFilename()
        if filename is None or len(filename) == 0:
            # No fixture setup required.
            return

        cls.console_printer = term.NullPrinter()
        cls.console_printer.start()

        (debugger, dbg_service) = dump.load_dump(filename, cls.console_printer.print_q,
                                                 config=DbgTestCase.get_debug_config())
        cls.debugger = debugger
        cls.dbg_service = dbg_service

        # Note: We do not need to call debugger.get_cmd_lock() as this is now performed
        # automatically within load_dump() before returning a debugger to us.



    @classmethod
    def tearDownClass(cls):
        if cls.dbg_service:
            cls.dbg_service.shutdown()

        if cls.debugger:
            cls.debugger.release_cmd_lock()  # Done.
            cls.debugger.close()

        if cls.console_printer:
            cls.console_printer.shutdown()


    def _get_datatype_for(self, sym_or_type):
        """
        Helper method to access a datatype / debuginfo entry a la `type <foo>`

        returns (kind, typ) where kind is a types.KIND_* enum and typ is the
        types.PrgmType, MethodInfo, or VariableInfo retrieved.
        """
        registers = self.debugger.get_registers()
        self.assertIsInstance(registers, dict)
        pc = registers["PC"]
        self.assertIsInstance(pc, int)
        self.assertGreater(pc, 0)
        return self.debugger.get_debug_info().getNamedDebugInfoEntry(sym_or_type, pc)

