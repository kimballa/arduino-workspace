# (c) Copyright 2022 Aaron Kimball
#
# Methods and constants for working with the terminal and VT100 emulation.

COLOR_WHITE     = '\033[0m'
COLOR_BOLD      = '\033[1m' # High-intensity white on black
COLOR_UNDERLINE = '\033[4m'
COLOR_INVERSE   = '\033[7m' # black on white

COLOR_GRAY      = '\033[90m'
COLOR_RED       = '\033[91m'
COLOR_GREEN     = '\033[92m'
COLOR_YELLOW    = '\033[93m'
COLOR_BLUE      = '\033[94m'
COLOR_PURPLE    = '\033[95m'
COLOR_CYAN      = '\033[96m'

BOLD      = COLOR_BOLD

ERR       = COLOR_RED
WARN      = COLOR_YELLOW
SUCCESS   = COLOR_GREEN

COLOR_OFF = COLOR_WHITE # Normal white on black


def use_colors(debugger):
    """
    Return true if we should use color in formatting output.
    """
    return debugger is not None and debugger.get_conf("dbg.colors")

def fmt(debugger, color_code, text):
    """
    Return a string wrapped in the codes to enable a certain color, if use_colors is active.
    """
    if use_colors(debugger):
        return f'{color_code}{text}{COLOR_OFF}'
    else:
        return text

