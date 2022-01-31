# (c) Copyright 2021 Aaron Kimball
#
# Methods that pipe out to programs included in gnu binutils
# (c++filt, addr2line).

import locale
import re
import subprocess

# undesirable suffixes on demangled names
_clone_regex = re.compile(r'\[clone \.[A-Za-z_]+.*\]$')


def demangle(name, hide_params=False):
    """
        Use c++filt in binutils to demangle a C++ name into a human-readable one.
        @
    """
    if name is None:
        return None
    args = ['c++filt', name]
    if hide_params:
        args.append('-p')  # Suppress method arguments in output.
    pipe = subprocess.Popen(args, stdin=None, stdout=subprocess.PIPE,
                            encoding=locale.getpreferredencoding())
    stdout, _ = pipe.communicate()
    demangled_list = stdout.split("\n")
    demangled = demangled_list[0].strip()

    # Remove any '[clone .constprop.NN]', etc suffixes.
    demangled = _clone_regex.sub('', demangled)

    # print(f"Demangled: {name} -> {demangled}")
    return demangled


def pc_to_source_line(elf_file, addr):
    """
        Given a program counter ($PC) value, establish what line of source it comes from.
    """
    if addr is None:
        return None
    args = ["addr2line", "-s", "-e", elf_file, ("%x" % addr)]
    pipe = subprocess.Popen(args, stdin=None, stdout=subprocess.PIPE,
                            encoding=locale.getpreferredencoding())
    stdout, _ = pipe.communicate()
    source_lines = stdout.split("\n")
    src_line = source_lines[0]
    if src_line.startswith("??:"):
        return None
    return src_line

