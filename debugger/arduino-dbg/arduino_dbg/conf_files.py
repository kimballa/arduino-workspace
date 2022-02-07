# (c) Copyright 2022 Aaron Kimball
"""
Capabilities to load and manage config files related to platform and architecture specs.
"""

import importlib.resources as resources

from arduino_dbg.repl_command import CompoundCommand, CompoundHost
from arduino_dbg.term import MsgLevel

CONF_MODULES = [
    "arduino_dbg.arch",         # chip-level architecture configs (e.g. 'atmega32u4')
    "arduino_dbg.platforms",    # Arduino assembly names ('uno', 'leonardo', etc.)
    ]



def load_conf_module(module_name, resource_name, print_q):
    """
        Open a resource (file) within a module with a '.conf' extension and treat it like python
        code; execute it in a sheltered environment and return the processed globals as a k-v map.

        We use this for Arduino Platform and cpu architecture (Arch) definitions.
    """
    if resource_name is None or len(resource_name) == 0:
        return None  # Nothing to load.

    if module_name not in CONF_MODULES:
        raise RuntimeError(
            f"Security violation: Cannot load conf file from module '{module_name}'.")

    conf_resource_name = resource_name.strip() + ".conf"
    conf_text = resources.read_text(module_name, conf_resource_name)
    conf = {}  # Create an empty environment in which to run the config code.

    def _include_fn(extra_resource_name):
        """
            Provide an 'include' method within the exec() scope so a .conf file can include
            more .conf files. This is restricted to the same module_name as the exterior binding
            scope.
        """
        included_map = load_conf_module(module_name, extra_resource_name, print_q)
        # Copy the items from the included map into the namespace of the including conf file
        for (k, v) in included_map.items():
            conf[k] = v

        return None

    conf['include'] = _include_fn  # Give the 'include' function to the scope.
    try:
        exec(conf_text, conf, conf)
        del conf["__builtins__"]  # Pull python internals from gloabls map we're using as config.
        del conf["include"]  # Pull out the include() function we provided.

        # Remove any "__private" items.
        to_delete = []
        for (k, v) in conf.items():
            if isinstance(k, str) and k.startswith("__"):
                to_delete.append(k)
        for key in to_delete:
            del conf[key]

    except Exception:
        # Error parsing/executing conf; return empty result.
        print_q.put(("Error loading config profile: %s" % conf_resource_name, MsgLevel.ERR))
        return None

    print_q.put(("Loading config profile: %s; read %d keys" % (conf_resource_name, len(conf)),
                MsgLevel.INFO))
    # conf is now populated with the globals from executing the conf file.
    return conf



@CompoundHost
class ConfFileCommands(object):
    """
    Repl commands for working with platform and architecture configs.
    """

    def __init__(self, repl):
        self._repl = repl

    def _print_list(self, pkg):
        """
        Actually iterate through the package in question and print the list of .conf
        files the user can load.
        """
        configs = []
        for item in resources.contents(pkg):
            if not item.endswith(".conf"):
                continue  # Ignore
            elif item.endswith("_common.conf"):
                continue  # Ignore; this is not a complete config unto itself.
            cfg = item[0:len(item) - len(".conf")]
            configs.append(cfg)

        self._repl.debugger().msg_q(MsgLevel.INFO, '\n'.join(configs))


    @CompoundCommand(kw1=['list'], kw2=['architectures', 'arch'], cls='ConfFileCommands')
    def list_arch(self, argv):
        """
        List available CPU architectures.

            Syntax: list arch[itectures]

        These can be used as inputs to `set arduino.arch = <some_arch>`. However, the
        CPU architecture is usually loaded based on the Arduino platform you are working
        with. See `list platforms` for more details.
        """
        self._print_list("arduino_dbg.arch")


    @CompoundCommand(kw1=['list'], kw2=['platforms'], cls='ConfFileCommands')
    def list_platforms(self, argv):
        """
        List available Arduino platforms

            Syntax: list platforms

        These can be used as inputs to `set arduino.platform = <some_platform>`.
        This will in turn set the `arduino.arch` property based on the CPU associated
        with the platform in question.

        You can, however, override that choice after loading the platform using
        `set arduino.arch = <arch>`. See `list architectures` for more details.
        """
        self._print_list("arduino_dbg.platforms")
