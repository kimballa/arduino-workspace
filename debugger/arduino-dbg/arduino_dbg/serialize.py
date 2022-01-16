# (c) Copyright 2022 Aaron Kimball

DBG_CONF_FMT_VERSION = 1

def load_config_file(filename, map_name='config', defaults=None):
    """
        Read a debugger configuration file map.
        This is actually a python file that will be evaluated in a sterile environment.
        It should contain two variables afterward:
        - `formatversion` specifies this serialization version
        - `{map_name}` is a dict of k-v pairs.

        If `defaults` is a map, then its values populate anything omitted from the loaded map.

        TODO(aaron): This is insecure.
    """
    if defaults is None:
        defaults = {}
    new_conf = defaults.copy()

    # The loaded config will be a map named '{map_name}' within an otherwise-empty environment
    init_env = {}
    init_env[map_name] = {}

    with open(filename, "r") as f:
        conf_text = f.read()
        try:
            exec(conf_text, init_env, init_env)
        except:
            # error parsing or executing the config file.
            print("Warning: error parsing config file '%s'" % filename)
            init_env[map_name] = {}
            init_env['formatversion'] = DBG_CONF_FMT_VERSION

    try:
        fmtver = init_env['formatversion']
        if not isinstance(fmtver, int) or fmtver > DBG_CONF_FMT_VERSION:
            print(f"Error: Cannot read config file '{filename}' with version {fmtver}")
            init_env[map_name] = {} # Disregard the unsupported configuration data.

        loaded_conf = init_env[map_name]
    except:
        print(f"Error in format for config file '{filename}'")
        loaded_conf = {}

    # Merge loaded data on top of our default config.
    for (k, v) in loaded_conf.items():
        new_conf[k] = v

    return new_conf


def __persist_conf_var(f, k, v):
    """
        Persist k=v in serialized form to the file handle 'f'.

        Can be called with k=None to serialize a nested value in a complex type.
    """

    if k is not None:
        f.write(f'  {repr(k)}: ')

    if v is None or type(v) == str or type(v) == int or type(v) == float or type(v) == bool:
        f.write(repr(v))
    elif type(v) == bytes or type(v) == bytearray:
        f.write(repr(bytes(v)))
    elif type(v) == list:
        f.write('[')
        for elem in v:
            __persist_conf_var(f, None, elem)
            f.write(", ")
        f.write(']')
    elif type(v) == dict:
        f.write("{\n")
        for (dirK, dirV) in v.items():
            f.write('    ')
            __persist_conf_var(f, None, dirK) # keys in a dir can be any type, not just str
            f.write(": ")
            __persist_conf_var(f, None, dirV)
            f.write(",\n")
        f.write("  }")
    else:
        print("Warning: unknown type serialization '%s'" % str(type(v)))
        # Serialize it as an abstract map; filter out python internals and methods
        objdir = dict([(dirK, dirV) for (dirK, dirV) in dir(v).items() if \
            (not dirK.startswith("__") and not dirK.endswith("__") and \
            not callable(getattr(v, dirK))) ])

        __persist_conf_var(f, None, objdir)

    if k is not None:
        f.write(",\n")


def persist_config_file(filename, map_name, data):
    """
        Write configuration information out to a file.
    """

    with open(filename, "w") as f:
        f.write(f"formatversion = {DBG_CONF_FMT_VERSION}\n")
        f.write(f"{map_name} = {{\n\n")
        for (k, v) in data.items():
            __persist_conf_var(f, k, v)
        f.write("\n}\n")

