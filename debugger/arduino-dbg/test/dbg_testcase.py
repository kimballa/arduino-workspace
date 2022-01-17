# (c) Copyright 2022 Aaron Kimball

import arduino_dbg.debugger as debugger
import arduino_dbg.dump as dump
import arduino_dbg.repl as repl

import unittest

class DbgTestCase(unittest.TestCase):
    """
    TestCase subclass that loads a core dump and ELF into a local Debugger
    session as a fixture.

    You must implement getDumpFilename() as a @classmethod to specify the
    dump file to load.
    - This filename should be relative to this 'test' directory, which is the cwd for the test.
    - If this dump loads an ELF file, the elf_file_name parameter in the dump file should
      also be relative to this 'test' directory.
    """

    console_printer = None
    debugger = None
    dbg_service = None

    @classmethod
    def classSetUp(cls):
        filename = cls.getDumpFilename()
        if filename is None or len(filename) == 0:
            # No fixture setup required.
            return

        cls.console_printer = repl.ConsolePrinter()
        cls.console_printer.start()

        (debugger, dbg_service) = dump.load_dump(filename, cls.console_printer.print_q)
        cls.debugger = debugger
        cls.dbg_service = dbg_service


    @classmethod
    def classTearDown(cls):
        if cls.dbg_service:
            cls.dbg_service.shutdown()

        if cls.debugger:
            cls.debugger.close()

        if cls.console_printer:
            cls.console_printer.shutdown()


