# (c) Copyright 2021 Aaron Kimball

import argparse

from .debugger import Debugger


def _parseArgs():
    parser = argparse.ArgumentParser(description="Serial debugger client for Arduino apps")
    parser.add_argument("-p", "--port", required=True)
    parser.add_argument("-f", "--file", metavar="elf_file")

    return parser.parse_args()

def main(argv):
    args = _parseArgs()
    d = Debugger(args.file, args.port)
