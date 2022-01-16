# (c) Copyright 2021 Aaron Kimball

import argparse
import sys

from .debugger import Debugger
from .repl import Repl
import arduino_dbg.io as io


def _parseArgs():
    parser = argparse.ArgumentParser(description="Serial debugger client for Arduino apps")
    parser.add_argument("-p", "--port")
    parser.add_argument("-f", "--file", metavar="elf_file")

    return parser.parse_args()

def main(argv):
    args = _parseArgs()
    if args.port:
        connection = io.SerialConn(args.port, 57000, 1)
    else:
        print("No serial connection specified. Use 'load <filename>' to load a dump file.")
        connection = None

    debugger = Debugger(args.file, connection)
    ret = 1
    repl = Repl(debugger)

    try:
        ret = repl.loop()
    finally:
        repl.close()

    sys.exit(ret)

