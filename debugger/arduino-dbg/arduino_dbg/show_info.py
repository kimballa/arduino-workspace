# (c) Copyright 2022 Aaron Kimball

"""
Commands to show helpful info to users.
"""

import arduino_dbg.conf_files as conf_files
from arduino_dbg.repl_command import CompoundCommand, CompoundHost
from arduino_dbg.term import MsgLevel
import arduino_dbg.version as version

# A list of feature-set capabilities supported by this debugger version.
# This starter list is hard-coded here, but other dynamic plugins can augment this
# list dynamically.
CAPABILITIES = [
    'cpu-autodetect',
    'offline-images',  # Dumping and offline examination of system snapshot.
    'term-colors',
    'term-history',
]


def get_capabilities_list(debugger):
    """
    Return a complete capabilities list, which includes CAPABILITIES as well as any
    dynamically-loaded capabilities.
    """
    return CAPABILITIES + debugger.arch_iface.get_capabilities_list()


@CompoundHost
class ShowCommands(object):
    """
    Repl commands to show useful info to users.
    """

    def __init__(self, repl):
        self._repl = repl
        self._conf_file_cmds = conf_files.ConfFileCommands(repl)


    @CompoundCommand(kw1=['show'], kw2=['version'], cls='ShowCommands')
    def print_version(self, argv):
        """
        Print debugger version

            Syntax: show version
        """
        self._repl.debugger().msg_q(MsgLevel.INFO, version.FULL_DBG_VERSION_STR)

    @CompoundCommand(kw1=['show'], kw2=['license'], cls='ShowCommands')
    def print_license(self, argv):
        """
        Print debugger license terms

            Syntax: show license
        """
        debugger = self._repl.debugger()
        debugger.msg_q(MsgLevel.INFO, version.FULL_DBG_VERSION_STR)
        debugger.msg_q(MsgLevel.INFO, '')
        debugger.msg_q(MsgLevel.INFO, version.LICENSE)

    @CompoundCommand(kw1=['show'], kw2=['capabilities'], cls='ShowCommands')
    def show_capabilities(self, argv):
        """
        Print a list of capabilities supported by this debugger

            Syntax: show capabilities
        """
        debugger = self._repl.debugger()

        # TODO(aaron): Allow autodetection of terminal width.
        max_term_width = 70

        # Create a list of the "feature set" we advertise and print it.
        capability_lst = get_capabilities_list(debugger).copy()
        capability_lst.sort()  # Sort alphabetically.
        out = []
        width = 0
        for cap in capability_lst:
            width += len(cap) + 2
            if width > max_term_width:
                # This would be too long for line; spill list for line so far.
                debugger.msg_q(MsgLevel.INFO, ', '.join(out) + ',')
                out = []
                width = len(cap) + 2

            out.append(cap)

        # Spill final list.
        debugger.msg_q(MsgLevel.INFO, ', '.join(out))

        # Show lists of supported hardware.
        debugger.msg_q(MsgLevel.INFO, '')
        debugger.msg_q(MsgLevel.INFO, 'Supported Arduino platforms')
        debugger.msg_q(MsgLevel.INFO, '---------------------------')
        self._conf_file_cmds.list_platforms([])

        debugger.msg_q(MsgLevel.INFO, '')
        debugger.msg_q(MsgLevel.INFO, 'Supported CPU architectures')
        debugger.msg_q(MsgLevel.INFO, '---------------------------')
        self._conf_file_cmds.list_arch([])


