# (c) Copyright 2021 Aaron Kimball

import argparse
import sys

from .debugger import Debugger
from .repl import Repl
from .term import ConsolePrinter
import arduino_dbg.io as io


def _parseArgs():
    parser = argparse.ArgumentParser(description="Serial debugger client for Arduino apps")
    parser.add_argument("-p", "--port")
    parser.add_argument("-f", "--file", metavar="elf_file")

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
        debugger = Debugger(args.file, connection, console_printer.print_q)
        console_printer.join_q()
        repl = Repl(debugger, console_printer)
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

