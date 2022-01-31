# (c) Copyright 2022 Aaron Kimball
#
# Methods and constants for working with the terminal and VT100 emulation.

import queue
import readline
import threading

# Change this flag to enable/disable color formatting.
enable_colors = True

COLOR_WHITE     = '\033[0m'
COLOR_BOLD      = '\033[1m'  # High-intensity white on black
COLOR_UNDERLINE = '\033[4m'
COLOR_INVERSE   = '\033[7m'  # black on white

COLOR_GRAY      = '\033[90m'
COLOR_RED       = '\033[91m'
COLOR_GREEN     = '\033[92m'
COLOR_YELLOW    = '\033[93m'
COLOR_BLUE      = '\033[94m'
COLOR_PURPLE    = '\033[95m'
COLOR_CYAN      = '\033[96m'

BOLD      = COLOR_BOLD

INFO      = COLOR_WHITE
SUCCESS   = COLOR_GREEN
WARN      = COLOR_YELLOW
ERR       = COLOR_RED

COLOR_OFF = COLOR_WHITE  # Normal white on black

# Repl prompt.
#
# Start with a CR (\r) to force reset to beginning of line in case async printing from the
# ConsolePrinter advances the cursor. Wrap that in \001..\002 to tell readline to
# disregard the \r in character counting; otherwise it sometimes continues to display a
# character of old input in place right after the prompt and before the real user input.
#
# see e.g.:
# https://stackoverflow.com/questions/8806643/colorized-output-breaks-linewrapping-with-readline/8916332#8916332
NO_CTRL_PROMPT = "(adbg) "              # The actual text we want to appear.
PROMPT = f'\001\r\002{NO_CTRL_PROMPT}'  # The prompt for readline to use, with leading ctrl chars.


def use_colors():
    """
    Return true if we should use color in formatting output.
    """
    return enable_colors


def set_use_colors(do_use_colors):
    global enable_colors
    enable_colors = do_use_colors


def fmt(text, color_code=None):
    """
    Return a string wrapped in the codes to enable a certain color, if use_colors is active.
    """
    if text == '':
        return ''
    elif use_colors() and color_code is not None:
        return f'{color_code}{text}{COLOR_OFF}'
    else:
        return text


def write(text, color_code=None):
    """
    Print a string. The String is first wrapped in the codes to enable a certain color, if
    use_colors is active.
    """
    print(fmt(text, color_code))


class MsgLevel(object):
    """
    Priority level codes for messages submitted to ConsolePrinter; used to colorize
    messages appropriately.
    """
    INFO        = 0         # Standard message
    DEVICE      = 1         # Message from the device (dbgprint(), etc)
    WARN        = 2         # Warnings
    ERR         = 3         # Errors
    DEBUG       = 4         # verboseprint() info from Debugger.
    SUCCESS     = 5         # Successful.

    @staticmethod
    def color_for_msg(msg_level):
        """
        Return a term color for the message level.
        """
        if msg_level is None:
            return INFO

        if msg_level == MsgLevel.INFO:
            return INFO
        elif msg_level == MsgLevel.DEVICE:
            return COLOR_CYAN
        elif msg_level == MsgLevel.WARN:
            return WARN
        elif msg_level == MsgLevel.ERR:
            return ERR
        elif msg_level == MsgLevel.DEBUG:
            return COLOR_GRAY
        elif msg_level == MsgLevel.SUCCESS:
            return SUCCESS
        elif isinstance(msg_level, str):
            # Actually this is a string... assume it's a raw term color code
            return msg_level
        else:
            return INFO


class ConsolePrinter(object):
    """
    Monitor that creates a queue of things to print to the console.
    Other threads may enqueue new text lines for printing.
    Refreshes the readline prompt (if one is active) after each line is printed.

    The primary use-case is printing messages that come in asynchronously from a
    running connected device while the main thread is blocking on the readline
    prompt.
    """

    TIMEOUT = 0.100  # Blink when reading the queue every 100ms..

    def __init__(self):
        # Batched print performance tops out around n=32 dequeues/context switch.
        self.print_q = queue.Queue(maxsize=32)
        self._alive = True
        self._readline_enabled = False
        self._thread = threading.Thread(
            target=self.service, name='Console print thread',
            daemon=True)  # This thread must not hold the process open.

    def start(self):
        self._thread.start()

    def shutdown(self):
        self._alive = False
        self._thread.join()

    def set_readline_enabled(self, rl_enabled):
        """
        If readline is enabled, then printing from this async source will
        re-print the console prompt.
        """
        self._readline_enabled = rl_enabled

    def join_q(self):
        """
        Wait for any pending items to be printed and drained from the queue.
        """
        self.print_q.join()

    def service(self):
        """
        Main service loop for thread. Receive lines to print and print them to stdout.
        """
        ENDL = "\n"

        while self._alive:
            to_print = []
            accepted = 0

            try:
                (textline, prio) = self.print_q.get(block=True, timeout=ConsolePrinter.TIMEOUT)
                to_print.append(fmt(textline, MsgLevel.color_for_msg(prio)))
                accepted += 1
                while self.print_q.qsize() > 0:
                    # If multiple messages are queued up, grab them in batch.
                    try:
                        (textline, prio) = self.print_q.get(block=False)
                        to_print.append(fmt(textline, MsgLevel.color_for_msg(prio)))
                        accepted += 1
                    except queue.Empty:
                        # Didn't actually have more to read.
                        break  # Break out of inner greedy-read loop.
            except queue.Empty:
                assert len(to_print) == 0
                assert accepted == 0
                continue

            if accepted == 0:
                # Nothing to do here.
                continue

            if self._readline_enabled and _readline_input_on:
                cur_input = readline.get_line_buffer()
            else:
                cur_input = ''

            # Blank out the prompt / input line and print the received text.

            print(f'\r{(len(PROMPT) + len(cur_input)) * " "}\r{ENDL.join(to_print)}', flush=True)

            if self._readline_enabled and _readline_input_on:
                # Refresh the visible console prompt
                print(f'\r{NO_CTRL_PROMPT}{cur_input}', end='', flush=True)

            for i in range(0, accepted):
                # Acknowledge all the messages we accepted at once.
                self.print_q.task_done()


class NullPrinter(ConsolePrinter):
    """
    ConsolePrinter implementation that just silently console all text it receives.
    """

    def __init__(self):
        super().__init__()

    def service(self):
        while self._alive:
            try:
                (textline, prio) = self.print_q.get(block=True, timeout=ConsolePrinter.TIMEOUT)
            except queue.Empty:
                continue

            self.print_q.task_done()


# Set to true only while the input() prompt is actually active.
# Use term.readline_input() instead of just calling input() to
# track this flag appropriately.
_readline_input_on = False


def readline_input():
    """
    Display readline-enabled prompt and return the input result.

    Set guard flags appropriately as we enter and exit the prompt
    to play nicely with the ConsolePrinter.
    """
    global _readline_input_on

    _readline_input_on = True
    try:
        return input(PROMPT)
    finally:
        _readline_input_on = False

