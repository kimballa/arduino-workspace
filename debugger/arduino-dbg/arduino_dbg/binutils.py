# (c) Copyright 2021 Aaron Kimball

import locale
import subprocess

def demangle(name):
    """
        Use c++filt in binutils to demangle a C++ name into a human-readable one.
    """
    args = ['c++filt', '-t', name]
    pipe = subprocess.Popen(args, stdin=None, stdout=subprocess.PIPE,
        encoding=locale.getpreferredencoding())
    stdout, _ = pipe.communicate()
    demangled = stdout.split("\n")
    return demangled[0]


def pc_to_source_line(elf_file, addr):
    """
        Given a program counter ($PC) value, establish what line of source it comes from.
    """
    args = ["addr2line", "-s", "-e", elf_file, ("%x" % addr)]
    pipe = subprocess.Popen(args, stdin=None, stdout=subprocess.PIPE,
        encoding=locale.getpreferredencoding())
    stdout, _ = pipe.communicate()
    source_lines = stdout.split("\n")
    return source_lines[0]

