# (c) Copyright 2021 Aaron Kimball
#
# Methods that pipe out to programs included in gnu binutils
# (c++filt, addr2line).

import locale
import re
import subprocess

# undesirable suffix on demangled names
_constprop_regex = re.compile(r'\[clone \.constprop.*\]$')


def demangle(name):
    """
        Use c++filt in binutils to demangle a C++ name into a human-readable one.
    """
    args = ['c++filt', '-t', name]
    pipe = subprocess.Popen(args, stdin=None, stdout=subprocess.PIPE,
        encoding=locale.getpreferredencoding())
    stdout, _ = pipe.communicate()
    demangled_list = stdout.split("\n")
    demangled = demangled_list[0].strip()

    # Remove any '[clone .constprop.NN]' suffix.
    demangled = _constprop_regex.sub('', demangled)

    return demangled


def pc_to_source_line(elf_file, addr):
    """
        Given a program counter ($PC) value, establish what line of source it comes from.
    """
    args = ["addr2line", "-s", "-e", elf_file, ("%x" % addr)]
    pipe = subprocess.Popen(args, stdin=None, stdout=subprocess.PIPE,
        encoding=locale.getpreferredencoding())
    stdout, _ = pipe.communicate()
    source_lines = stdout.split("\n")
    src_line = source_lines[0]
    if src_line.startswith("??:"):
        return None
    return src_line

