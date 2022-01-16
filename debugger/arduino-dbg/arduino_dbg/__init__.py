# (c) Copyright 2021 Aaron Kimball

import argparse
import sys

from .debugger import Debugger
from .repl import Repl
import arduino_dbg.io as io


def _parseArgs():
    parser = argparse.ArgumentParser(description="Serial debugger client for Arduino apps")
    parser.add_argument("-p", "--port", required=True)
    parser.add_argument("-f", "--file", metavar="elf_file")

    return parser.parse_args()

def main(argv):
    args = _parseArgs()
    connection = io.SerialConn(args.port, 57000, 1)
    debugger = Debugger(args.file, connection)
    ret = 1
    try:
        repl = Repl(debugger)
        ret = repl.loop()
    finally:
        debugger.close()

    sys.exit(ret)

