# (c) Copyright 2021 Aaron Kimball

import argparse
import serial

class Debugger(object):
    def __init__(self, port, baud=9600, timeout=1):
        self._conn = None
        self.reopen(port, baud, timeout)

    def close(self):
        self._conn.close()
        self._conn = None

    def reopen(self, port, baud, timeout):
        if self._conn is not None:
            self.close()

        self._conn = serial.Serial(port, baud, timeout=timeout)


    
def _parseArgs():
    parser = argparse.ArgumentParser(description="Serial debugger client for Arduino apps")
    parser.add_argument("-p", "--port", required=True)
    parser.add_argument("-f", "--file", metavar="elf_file")

    return parser.parse_args()

def main(argv):
    args = _parseArgs()
    d = Debugger(args.port)
