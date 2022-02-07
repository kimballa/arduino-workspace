# (c) Copyright 2021 Aaron Kimball
"""
CPU Architecture-specific concerns.
"""

from arduino_dbg.term import MsgLevel


# Map from class names to classes that fulfill the ArchInterface contract.
ARCH_INTERFACES = {}
__arch_interfaces_loaded = False


def iface(cls):
    """
    Decorator that adds an ArchInterface class to the set that can be spawned based on the selected
    arch_conf.
    """
    ARCH_INTERFACES[cls.__name__] = cls
    return cls


def load_arch_interfaces():
    """
    Load all the architecture interface modules, which triggers them to
    each call register_arch_interface() with their specific class.
    """
    global __arch_interfaces_loaded
    if __arch_interfaces_loaded:
        return  # No further work to do.

    # We don't literally use these modules in this method but their loading
    # populates ARCH_INTERFACES via calls to register_arch_interface.
    import arduino_dbg.arch.avr_interface       # noqa: F401
    import arduino_dbg.arch.thumb_interface     # noqa: F401

    __arch_interfaces_loaded = True  # Only need to run this method once.


class ArchNotSupportedError(Exception):
    """ Architecture / ArchInteface does not support a particular method. """
    pass


class ArchInterface(object):
    """
    A module to hold various methods invoked by the debugger that need to perform
    differently depending on the CPU architecture.
    """

    def __init__(self, debugger):
        self.debugger = debugger

    def __repr__(self):
        return self.__class__.__name__

    def true_pc(self, mem_pc):
        """
        Given a $PC value word as read from register or stack, return the true PC
        value this represents.
        """
        return mem_pc

    def stack_frame_size_for_prologue(self, pc, method_sym):
        raise ArchNotSupportedError()


    @staticmethod
    def make_arch_interface(debugger):
        """
        Factory method to provide the correct ArchInterface implementation for the
        current debugger config.
        """
        iface_name = debugger.get_arch_conf("arch_interface")
        if iface_name not in ARCH_INTERFACES:
            debugger.msg_q(MsgLevel.WARN, f"Warning: Unknown architecture interface: {iface_name}")
            return None

        debugger.verboseprint(f'Loading debugger architecture interface: {iface_name}')
        return ARCH_INTERFACES[iface_name](debugger)

