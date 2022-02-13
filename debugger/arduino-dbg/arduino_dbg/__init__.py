# (c) Copyright 2021 Aaron Kimball

import argparse
import sys
import arduino_dbg.version as version

DBG_VERSION = version.DBG_VERSION
DBG_VERSION_STR = version.DBG_VERSION_STR
FULL_DBG_VERSION_STR = version.FULL_DBG_VERSION_STR
__version__ = DBG_VERSION_STR


def _parseArgs():
    parser = argparse.ArgumentParser(description="Serial debugger client for Arduino apps")
    parser.add_argument("-p", "--port")
    parser.add_argument("-f", "--file", metavar="elf_file")
    parser.add_argument("-d", "--dump", metavar="dump_file")
    parser.add_argument("-v", "--version", action="version", version=FULL_DBG_VERSION_STR)

    return parser.parse_args()


def main():
    # Delay loading real dependencies into main so that setup.py can load arduino_dbg.version
    # without relying on any real dependencies of this system.
    from .debugger import Debugger
    from .repl import Repl
    from .term import ConsolePrinter
    import arduino_dbg.binutils as binutils
    import arduino_dbg.dump as dump
    import arduino_dbg.io as io

    ret = 1
    args = _parseArgs()
    connection = None
    if args.port:
        connection = io.SerialConn(args.port, 57600, 0.1)

    main_owns_printer = True
    console_printer = ConsolePrinter()
    try:
        binutils.start_demangle_threads(console_printer.print_q)
        console_printer.start()
        if args.dump:
            # Create a Debugger for the specfified dump file.
            if args.file or args.port:
                print("Loading dump file; ignoring ELF file / serial port settings.")
            debugger, hosted_dbg_serv = dump.load_dump(args.dump, console_printer.print_q)
        else:
            # Normal debugger instantiation
            hosted_dbg_serv = None
            debugger = Debugger(args.file, connection, console_printer.print_q)
        console_printer.join_q()
        repl = Repl(debugger, console_printer, hosted_dbg_serv)
        main_owns_printer = False
    finally:
        # Once we create the Repl, it owns console_printer and will shut it down at any
        # point after this. But any exception here prevents that; shut it down cleanly
        # ourselves, first, to prevent its thread from hanging up program exit.
        if main_owns_printer:
            console_printer.shutdown()

        # Close any global c++filt DemangleThread instances opened up.
        binutils.close_demangle_threads()

    try:
        ret = repl.loop()
    finally:
        repl.close()

    sys.exit(ret)

