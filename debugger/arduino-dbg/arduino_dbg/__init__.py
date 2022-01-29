# (c) Copyright 2021 Aaron Kimball

import argparse
import sys

from .debugger import Debugger
from .repl import Repl
from .term import ConsolePrinter
import arduino_dbg.dump as dump
import arduino_dbg.io as io

DBG_VERSION = [ 0, 1, 0 ]
DBG_VERSION_STR = '.'.join(map(str, DBG_VERSION))
FULL_DBG_VERSION_STR = f'Arduino Debugger (adbg) version {DBG_VERSION_STR}'
__version__ = DBG_VERSION_STR

def _parseArgs():
    parser = argparse.ArgumentParser(description="Serial debugger client for Arduino apps")
    parser.add_argument("-p", "--port")
    parser.add_argument("-f", "--file", metavar="elf_file")
    parser.add_argument("-d", "--dump", metavar="dump_file")
    parser.add_argument("-v", "--version", action="version", version=FULL_DBG_VERSION_STR)

    return parser.parse_args()

def main(argv):
    ret = 1
    args = _parseArgs()
    connection = None
    if args.port:
        connection = io.SerialConn(args.port, 57600, 0.1)

    console_printer = ConsolePrinter()
    console_printer.start()
    try:
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
    except:
        # if we created the Repl, it would own console_printer and shut it down at any
        # point after this. But any exception here prevents that; shut it down cleanly
        # ourselves, first.
        console_printer.shutdown()
        raise

    try:
        ret = repl.loop()
    finally:
        repl.close()

    sys.exit(ret)

