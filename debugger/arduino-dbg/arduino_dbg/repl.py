# (c) Copyright 2021 Aaron Kimball

import functools
import inspect
import readline
import signal
from sortedcontainers import SortedDict, SortedList
import traceback

import arduino_dbg.binutils as binutils
import arduino_dbg.debugger as dbg
import arduino_dbg.protocol as protocol
import arduino_dbg.types as types

def _softint(intstr, base=10):
    """
        Try to convert intstr to an int; if it fails, return None instead of ValueError like int()
    """
    try:
        return int(intstr, base)
    except ValueError:
        return None


class Completions(object):
    """
    Enumeration of valid autocomplete token classes.
    These can be used as entries in the `completions` list argument to @Command, and
    are interpreted by the ReplAutocompleter to query the right set of possibilities.
    """
    NONE = ''                   # A token that is uncompletable. Used as 'filler' in the 
                                # completions list, before later completable token positions.
    KW = 'kw'                   # Another keyword that starts with the token as prefix.
    SYM = 'sym'                 # A symbol name that starts with the token as prefix.
    TYPE = 'type'               # A type name that starts with the token as prefix.
    SYM_OR_TYPE = 'sym/type'    # Either a symbol or a type name.
    WORD_SIZE = 'word_size'     # An integer that's a valid word size {1, 2, 4}.
    BINARY = 'binary'           # Values 0 and 1.
    BASE = 'base'               # integer base: 2, 8, 10, 16.
    CONF_KEY = 'conf_key'       # A configuration key.



class Command(object):
    """
    meta-decorator that tags a given function as a command that can be executed in the repl.
    Binds the keyword(s) to the function, registers the function's docstring as its help
    text, and the first non-empty line of the function's docstring as its short help text
    shown by the 'help' command.

    @param keywords is a list of keywords that trigger the command function.
    @return a decorator that directly returns its function argument unmodified.
    """

    _cmd_map = {}                 # Lookup from all keywords to Command instances
    _cmd_index = SortedDict()     # Set of Command instances keyed by primary keyword only.
    _cmd_list = SortedList()      # Sorted list of all keywords.
    _cmd_syntax_completions = {}  # Instructions indicating the kinds of tokens that can follow
                                  # each keyword, for use in tab autocompletion.

    def __init__(self, keywords, help_keywords=None, display_help=True, completions=None):
        self.keywords = keywords # Set of keywords that activate this command.
        self.help_keywords = help_keywords or [] # Additional keywords to display in cmd summary.
        self.command_func = None # The function to call (memoized in __call__)
        self.short_help = ''     # 1-line help summary extracted from fn docstring.
        self.long_help = ''      # Full help summary extracted from fn docstring.
        self.display_help = display_help # Does this show up in the command summary?

        if not isinstance(keywords, list):
            raise Exception("Expected syntax @Command(keywords=[...])")

        if keywords is None or len(keywords) == 0:
            raise Exception("Must supply one or more keywords to @command.")

        # Register binding from each keyword to this object.
        for kw in keywords:
            if Command._cmd_map.get(kw):
                raise Exception(f"Warning: keyword '{kw}' used multiple times")
            Command._cmd_map[kw] = self
            Command._cmd_list.add(kw)
            Command._cmd_syntax_completions[kw] = completions

        # Register this in the full command map
        Command._cmd_index[keywords[0]] = self

    def invoke(self, repl, args):
        """
        Actually invoke the command function we decorated.

        @param repl the repl instance that owns the method.
        @param args the arg array to pass to the method.
        """

        return self.command_func(repl, args) # repl is 'self' from pov of called method.

    def __call__(self, *args, **kwargs):
        """
        Memoize the actual function associated with this command, and extract help text
        from docstring.

            @Command(keywords=['x','y'])
            def some_fn(): ...

            is equivalent to:

            def some_fn(): ...
            some_fn = Command(keywords=['x','y'])(some_fn)

            ... is equivalent to...

            def some_fn(): ...
            c = Command(keywords=...)
            some_fn = c.__call__(some_fn)

        This callable method will be invoked with the function itself as the arg, to transform
        that function. We want to save the function argument as 'what we really invoke' and
        return the identity transformation in-place.

        """

        fn = args[0]
        self.command_func = fn # The function argument is what we'll call to run the command.

        # The long help (shown in `help <kwd>`) is the entire cleanly-reformatted docstring,
        # along with the list of keyword synonyms to invoke it.
        all_keywords = []
        all_keywords.extend(self.keywords)
        all_keywords.extend(self.help_keywords) # Some keywords like 'tm' show up as synonyms
                                                # for <X> without activating <X> directly.

        if len(all_keywords) > 1:
            keywordsIntro = f"{all_keywords[0]} ({', '.join(all_keywords[1:])})"
        else:
            keywordsIntro = f"{all_keywords[0]}"

        docstring = inspect.cleandoc(fn.__doc__)
        helptext = f"    {keywordsIntro}\n\n{docstring}"
        self.long_help = helptext

        # The short help (shown in the `help` summary) is the keyword list and
        # the first non-empty line of the docstring.
        docstr_lines = docstring.split("\n")
        if len(docstr_lines) == 1:
            self.short_help = f'{keywordsIntro} -- {docstring.strip()}'
        else:
            first_real_line = None
            for line in docstr_lines:
                if len(line.strip()) > 0:
                    first_real_line = line.strip()
                    break
            if first_real_line:
                self.short_help = f'{keywordsIntro} -- {first_real_line}'
            else:
                # Just use.. the entire (empty?) docstring
                self.short_help = f'{keywordsIntro} -- {docstring.strip()}'

        return fn

    @classmethod
    def getCommandMap(cls):
        """
        Return full mapping from keywords to Command instances.
        """
        return cls._cmd_map

    @classmethod
    def getCommandIndex(cls):
        """
        Return sorted mapping from primary keyword to Command instances.
        """
        return cls._cmd_index

    @classmethod
    def getCommandList(cls):
        """
        Return sorted list of keywords.
        """
        return cls._cmd_list

    @classmethod
    def getCommandCompletions(cls, keyword):
        """
        Return a list of completion tokens accepted by each keyword
        """
        return cls._cmd_syntax_completions[keyword]


class ReplAutoComplete(object):
    """
    readline autocompleter for debugger repl.
    """

    def __init__(self, debugger):
        self._debugger = debugger


    def complete_keyword(self, prefix):
        """
        Return completions for keyword
        """
        if prefix is None or len(prefix) == 0:
            nextfix = None
        else:
            last_char = prefix[-1]
            next_char = chr(ord(last_char) + 1)
            nextfix = prefix[0:-1] + next_char

        return Command.getCommandList().irange(prefix, nextfix, inclusive=(True,False))

    def complete_symbol(self, prefix):
        return self._debugger.syms_by_prefix(prefix)

    def complete_type(self, prefix):
        lst = SortedList()
        lst.update(types.types(prefix))
        return lst

    def complete_symbol_or_type(self, prefix):
        lst = SortedList()
        lst.update(self.complete_symbol(prefix))
        lst.update(self.complete_type(prefix))
        return lst

    def complete_conf_key(self, prefix):
        conf_keys = self._debugger.get_conf_keys()
        return list(filter(lambda key: key.startswith(prefix), conf_keys))

    def suggest(self, tokens, prefix):
        if len(tokens) == 0 or len(tokens) == 1:
            # We are trying to suggest the first token in the line, which is always a keyword.
            return self.complete_keyword(prefix)

        # Otherwise, we need to recommend a keyword-specific next token.
        keyword = tokens[0]
        arg_tokens = tokens[1:]
        # Get a list of the form [ clsA, clsB, clsC ] where clsA..C are strings in the
        # 'Completions' string enumeration. Each of these defines the set of things that
        # can be completed in each successive position of the arguments to the keyword.
        completion_sets = Command.getCommandCompletions(keyword)
        if completion_sets is None or len(completion_sets) < len(arg_tokens):
            # We can't complete this far into the token set for this command
            return []

        # Get the completion set relevant to the current token
        completion_set = completion_sets[len(arg_tokens) - 1]
        if completion_set == Completions.NONE:
            return [] # No suggestions
        elif completion_set == Completions.KW:
            return self.complete_keyword(prefix)
        elif completion_set == Completions.SYM:
            return self.complete_symbol(prefix)
        elif completion_set == Completions.TYPE:
            return self.complete_type(prefix)
        elif completion_set == Completions.SYM_OR_TYPE:
            return self.complete_symbol_or_type(prefix)
        elif completion_set == Completions.WORD_SIZE:
            return [ 1, 2, 4 ]
        elif completion_set == Completions.BINARY:
            return [ 0, 1 ]
        elif completion_set == Completions.BASE:
            return [ 2, 8, 10, 16 ]
        elif completion_set == Completions.CONF_KEY:
            return self.complete_conf_key(prefix)
        elif isinstance(completion_set, list):
            # Completion set is itself a set of explicit choices.
            return list(filter(lambda choice: choice.startswith(prefix), completion_set))

        # Don't know what this completion set is supposed to be.
        raise Exception(f"Unknown completion set: '{completion_set}'")


    def complete(self, prefix, state):
        """
        Main interface method for readline autocomplete.
        We are passed the current token to complete as 'text' and the iteration number in 'state'.
        Incrementally higher 'state' values should yield subsequently-indexed suggestions.
        """
        try:
            tokens = readline.get_line_buffer().split()
            if not tokens or readline.get_line_buffer()[-1] == ' ':
                tokens.append('')

            raw_results = list(self.suggest(tokens, prefix))
            results = [ rec + ' ' for rec in raw_results ]  # Add a space after each rec to advance token.
            results.append(None) # Append a 'None' to the end to signal
                                 # stop-iteration condition to readline.

            return results[state] # state is an index into the output list.

        except Exception as e:
            # readline swallows our exceptions. Print them out, because we need to know
            # what's going on.
            print(f'\nException in autocomplete: {e}')
            if self._debugger.get_conf("dbg.verbose"):
                traceback.print_tb(e.__traceback__)
            raise # rethrow


class Repl(object):
    """
    The interactive command-line the user interacts with directly.
    """

    def __init__(self, debugger):
        self._debugger = debugger

        signal.signal(signal.SIGINT, signal.default_int_handler)

        self._last_sym_search = []   # results of most-recent symbol substr search.
        self._last_sym_used = None   # last symbol referenced by the user.

        self._break_count = 0 # How many times has the user mashed ^C?


    @Command(keywords=['locals'])
    def _show_locals(self, argv):
        """
        Show info about local variables in a stack frame

            Syntax: locals <frame>

        Given a frame number (from a `backtrace` command), show info about local variables
        within the method scope at the current $PC.
        """
        if len(argv) == 0:
            print("Syntax: locals <frame>")
            return

        frameId = int(argv[0])
        frameScopes = self._debugger.get_frame_vars(frameId)
        frameRegs = self._debugger.get_frame_regs(frameId)
        if frameScopes is None:
            print(f'No such stack frame {frameId}')
            return

        nest = 0
        for scope in frameScopes:
            nest_str = nest * ' '
            if isinstance(scope, types.MethodInfo):
                if not scope.is_decl and not scope.is_def:
                    inl_str = 'Inlined method'
                else:
                    inl_str = 'Method'
                print(f'{nest_str}{inl_str} scope: {scope}')

            formals = scope.getFormals()
            if len(formals) > 0:
                print(f"{nest_str}  Formals:")
                for formal in formals:
                    formal_val = formal.getValue(frameRegs)
                    if formal_val is not None:
                        val_str = f' = {formal_val}'
                    else:
                        val_str = ''
                    print(f'{nest_str}  {formal.name}: {formal.arg_type.name}{val_str}')


            var_list = scope.getVariables()
            if len(var_list):
                print(f"{nest_str}  Locals:")
                for local_name, local_var in var_list:
                    if local_name is None:
                        continue
                    local_val = local_var.getValue(frameRegs)
                    if local_val is not None:
                        val_str = f' = {local_val}'
                    else:
                        val_str = ''
                    print(f'{nest_str}  {local_name}: {local_var.var_type.name}{val_str}')

            nest += 2


    @Command(keywords=['backtrace', '\\t'])
    def _backtrace(self, argv):
        """
        Show the function call stack
        Enumerates the method calls on the stack, along with the return point in the source.

            Syntax: backtrace

        This function lists all current stack frames by starting with $PC and $SP and walking
        up the stack to identify frame boundaries and method return points. The top-most call
        on the stack will be #0, followed by #1, #2, etc; 'main()' will be the bottom-most
        method named.

        See also the 'frame' command, which shows the stack memory for a specific stack frame.
        """
        frames = self._debugger.get_backtrace()
        for i in range(0, len(frames)):
            print(f"{i}. {frames[i]}")


    @Command(keywords=['break'])
    def _break(self, argv=None):
        """
        Interrupt program execution for debugging
        """
        self._debugger.send_break()


    @Command(keywords=['continue', 'c', '\\c'])
    def _continue(self, argv=None):
        """
        Continue main program execution
        Resumes execution after a breakpoint or interrupt.
        """
        self._debugger.send_continue()


    @Command(keywords=['flash', 'xf'], completions=[Completions.WORD_SIZE])
    def _flash(self, argv):
        """
        Read a flash address on the Arduino

            Syntax: flash [<size>] <addr (hex)>

        size must be 1, 2, or 4. Address must be in base 16 (hex).
        """

        if len(argv) == 0:
            print("Syntax: flash [<size>] <addr (hex)>")
            return
        elif len(argv) == 1:
            size = 1
            addr = int(argv[0], base=16)
        else:
            size = int(argv[0])
            addr = int(argv[1], base=16)

        if size < 1:
            size = 1
        elif size > 4 or size == 3:
            size = 4

        v = self._debugger.get_flash(addr, size)
        print(f"<{v}>")
        if size == 1:
            print(f"{v:02x}")
        elif size == 2:
            print(f"{v:04x}")
        elif size == 4:
            print(f"{v:08x}")

    @Command(keywords=['gpio'], completions=[Completions.NONE, Completions.BINARY])
    def _gpio(self, argv):
        """
        Read or write a GPIO pin

            Syntax: gpio <pinId> [<value>]

        This command can only write to pins already configured as outputs.
        """

        if len(argv) == 0:
            print("Syntax: gpio <pinId> [<value>]")
            return
        elif len(argv) == 1:
            try:
                pin = int(argv[0])
            except ValueError:
                print(f"Error: could not parse pin id {argv[0]}")
                return

            num_pins = self._debugger.get_platform_conf("gpio_pins")
            if pin < 0 or pin >= num_pins:
                print(f"Error: available gpio pins are between [0, {num_pins}).")

            v = self._debugger.get_gpio_value(pin)
            if v is not None:
                print(v)
        else:
            # 2+ args => set the pin value.
            try:
                pin = int(argv[0])
            except ValueError:
                print(f"Error: could not parse pin id {argv[0]}")
                return

            try:
                val = int(argv[1])
            except ValueError:
                print(f"Error: could not parse value ({argv[1]})")
                return

            if val != 0 and val != 1:
                print("Error: value must be 0 or 1")
                return

            num_pins = self._debugger.get_platform_conf("gpio_pins")
            if pin < 0 or pin >= num_pins:
                print(f"Error: available gpio pins are between [0, {num_pins}).")

            self._debugger.set_gpio_value(pin, val)


    @Command(keywords=['memstats'])
    def _memstats(self, argv):
        """
        Display info about memory map and RAM usage
        """
        mem_map = self._debugger.get_memstats()
        ram_end = mem_map["RAMEND"]
        ram_start = mem_map["RAMSTART"]
        total_ram = ram_end - ram_start + 1
        stack_size = ram_end - mem_map["SP"]
        if mem_map["HeapEnd"] != 0:
            heap_size = mem_map["HeapEnd"] - mem_map["HeapStart"]
        else:
            heap_size = 0 # No allocation performed

        global_size = mem_map["HeapStart"] - ram_start
        free_ram = total_ram - stack_size - heap_size - global_size

        print(f'   Total RAM:  {total_ram:>4}  RAMEND={ram_end:04x} .. RAMSTART={ram_start:04x}')
        print(f'  Stack size:  {stack_size:>4}      SP={mem_map["SP"]:04x}')
        print(f'      (free):  {free_ram:>4}')
        print(f'   Heap size:  {heap_size:>4}')
        print(f'     Globals:  {global_size:>4} (.data + .bss)')


    @Command(keywords=['mem', 'x', '\\m'], completions=[Completions.WORD_SIZE])
    def _mem(self, argv):
        """
        Read a memory address on the Arduino

            Syntax: mem [<size>] <addr (hex)>

        size must be 1, 2, or 4.
        """
        if len(argv) == 0:
            print("Syntax: mem [<size>] <addr (hex)>")
            return
        elif len(argv) == 1:
            size = 1
            addr = int(argv[0], base=16)
        else:
            size = int(argv[0])
            addr = int(argv[1], base=16)

        if size < 1:
            size = 1
        elif size > 4 or size == 3:
            size = 4

        v = self._debugger.get_sram(addr, size)
        if size == 1:
            print(f"{v:02x}")
        elif size == 2:
            print(f"{v:04x}")
        elif size == 4:
            print(f"{v:08x}")


    @Command(keywords=['poke'],
        completions=[Completions.NONE, Completions.NONE, Completions.WORD_SIZE, Completions.BASE])
    def _poke(self, argv):
        """
        Write to a variable or memory address on the Arduino

            Syntax: poke <addr (hex)> <value> [size=1] [base=10]

        This will write to any address in the Arduino's SRAM and can easily corrupt your program.
        To set the value of a global variable with a known symbol, see the `setv` command.
        """
        base = 10
        if len(argv) < 2:
            print("Syntax: poke <addr (hex)> <value> [size=1] [base=10]")
            return
        else:
            addr = argv[0]
            val = argv[1]

        if len(argv) > 2:
            size = argv[2]
        else:
            size = 1

        if len(argv) > 3:
            try:
                base = int(argv[3])
            except ValueError:
                print(f"Warning: could not set base={argv[3]}. Using base 10")
                base = 10

        # Convert argument to integer. (TODO(aaron): Handle floating point some day?)
        try:
            val = int(val, base=base)
        except ValueError:
            print(f"Error: Cannot parse integer value {val} in base {base}")
            return

        # Resolve memory address
        try:
            addr = int(addr, base=16)
        except ValueError:
            print(f"Error: Cannot parse memory address {addr} in base 16")
            return

        # Resolve size
        try:
            size = int(size)
        except ValueError:
            print(f"Error: Cannot parse memory size {size}")

        if size < 1:
            size = 1
        elif size > 4 or size == 3:
            size = 4

        data_addr_mask = self._debugger.get_arch_conf("DATA_ADDR_MASK")
        if data_addr_mask and (addr & data_addr_mask) == addr:
            # We're trying to update something in flash.
            print(f"Error: Cannot write to flash segment at address {addr:x}")
        else:
            # We're trying to update something in SRAM:
            self._debugger.set_sram(addr, val, size)


    @Command(keywords=['print', 'v', '\\v'], completions=[Completions.SYM])
    def _print(self, argv):
        """
        Print a global variable's value

            Syntax: print <symbol_name>

        After applying a 'print' command, the shorthand '$' will refer to the last symbol used.
        See also the 'setv' command to change the value of a symbol in RAM.
        """
        if len(argv) == 0:
            print("Syntax: print <symbol_name>")
            return

        sym = self._debugger.lookup_sym(argv[0])
        if sym is None:
            print(f"No symbol found: {argv[0]}")
            return

        self._last_sym_used = argv[0] # Symbol argument saved as last symbol used.

        addr = sym.addr
        size = 1 # set default...
        try:
            size = sym.size # override if available.
        except KeyError:
            pass

        if size < 1:
            size = 1
        elif size > 4 or size == 3:
            size = 4

        data_addr_mask = self._debugger.get_arch_conf("DATA_ADDR_MASK")
        if data_addr_mask and (addr & data_addr_mask) == addr:
            # We're requesting something in flash.
            v = self._debugger.get_flash(addr, size)
        else:
            # We're requesting something in SRAM:
            v = self._debugger.get_sram(addr, size)

        if size == 1:
            print(f"{v:02x}")
        elif size == 2:
            print(f"{v:04x}")
        elif size == 4:
            print(f"{v:08x}")


    def __format_registers(self, registers):
        """
        Actually format and print register values to the screen, for _regs() or _frame().
        """
        MAX_WIDTH = 65

        has_sph = self._debugger.get_arch_conf("instruction_set") == "avr" and \
            self._debugger.get_arch_conf("has_sph")

        cur_width = 0
        for (reg, regval) in registers.items():
            if reg == "SP" and has_sph:
                # if reg=SP and we have SPH in the arch conf, it's a 16-bit reg; use 04x for regval.
                print(f"{reg.rjust(4)}:{regval:04x} ", end='')
            else:
                # normal 8-bit register
                print(f"{reg.rjust(4)}:{regval:02x}  ", end='')

            cur_width += 9
            if cur_width >= MAX_WIDTH:
                cur_width = 0
                print("")

        print("")

    @Command(keywords=['regs'])
    def _regs(self, argv):
        """
        Print current values of registers
        """
        self.__format_registers(self._debugger.get_registers())


    @Command(keywords=['reset'])
    def _reset(self, argv=None):
        """
        Reset the Arduino device

        Execution resumes at the program entry point. This will disconnect the debugger.
        """
        self._debugger.reset_sketch()


    @Command(keywords=['set'], completions=[Completions.CONF_KEY])
    def _set_conf(self, argv):
        """
        Set or retrieve a config variable of the debugger

            Syntax: set [keyname [[=] value]]

        * If called with no arguments, this prints the entire config to stdout.
        * If called with just a setting name ("set foo"), print the setting value.
        * If called with "set keyname val", "set keyname = val", or "set keyname=val" then it updates
          the configuration with that value. If numeric, 'val' is assumed to be in base 10.

        Successful updates to the config are performed silently.
        Attempting to set a config key that does not exist will print an error message.

        Successful updates to the config cause the config to be persisted to a conf
        file in the user's home dir.
        """

        def _fmt_value(v, in_hex=False, quote_strs=False, level=0):
            """
                Format one value for printing. If in_hex is True, and the value is
                an integer, it will be formatted in base 16.

                Composite values inherit in_hex status through recursive calls.
                * _fmt_value(some_list, in_hex) will format the values of some_list according to
                  in_hex status.
                * _fmt_value(some_dict, in_hex) will format (k, v) pairs of the dict according to
                  `in_hex or str(k) == str(k).upper()`

                Strings are not-quoted by default; quote_strs is set to True for recursive calls
                for composite value formatting.
            """
            if callable(v):
                return "<function>"
            elif isinstance(v, int):
                if in_hex:
                    return f"0x{v:x}"
                else:
                    return f"{v}"
            elif isinstance(v, str):
                if quote_strs:
                    return f"'{v}'"
                else:
                    return v
            elif isinstance(v, list):
                items = [ _fmt_value(v2, in_hex, True, level+1) for v2 in v ]

                # Should we put these on a comma-delimited single line? Or wrap item-by-item onto
                # one line each? Depends on the max length of a single item.
                max_len = functools.reduce(max, [len(it) for it in items])
                if max_len < 50:
                    join_str = ", "
                else:
                    join_str = ",\n"
                    for i in range(0, level + 1):
                        join_str += "  "

                s = '[' + join_str.join(items) + ']'
                return s
            elif isinstance(v, dict):
                s = '{'
                items = []
                for (k2, v2) in v.items():
                    in_hex2 = in_hex or (isinstance(k2, str) and k2 == k2.upper())
                    items.append(f"{_fmt_value(k2, in_hex2, True, level+1)}: " +
                        f"{_fmt_value(v2, in_hex2, True, level+1)}")

                # Should we put these on a comma-delimited single line? Or wrap item-by-item onto
                # one line each? Depends on the max length of a single item.
                max_len = functools.reduce(max, [len(it) for it in items])
                if max_len < 50:
                    join_str = ", "
                else:
                    join_str = ",\n"
                    for i in range(0, level + 1):
                        join_str += "  "

                s += join_str.join(items)
                s += '}'
                return s
            else:
                return f"{v}"


        def _print_kv_pair(k, v):
            in_hex = isinstance(k, str) and k == k.upper() # CAPS keys are printed in hex.
            print(f"{k} = {_fmt_value(v, in_hex)}")


        if len(argv) == 0:
            ### No key argument -- display entire configuration ###
            print("Configurable debugger settings:")
            print("-------------------------------")
            for (k, v) in self._debugger.get_full_config():
                _print_kv_pair(k, v)

            print("")
            print("Arduino platform configuration:")
            print("-------------------------------")
            platform = self._debugger.get_full_platform_config()
            if len(platform) == 0:
                print("No platform set; configure with 'set arduino.platform ...'.")
            else:
                for (k, v) in platform:
                    _print_kv_pair(k, v)

            print("")
            print("CPU architecture configuration:")
            print("-------------------------------")
            arch = self._debugger.get_full_arch_config()
            if len(arch) == 0:
                print("No architecture set; configure 'set arduino.platform ...' or " +
                    "'set arduino.arch ...' directly.")
            else:
                for (k, v) in arch:
                    _print_kv_pair(k, v)

        elif len(argv) == 1 and len(argv[0].split("=", 1)) == 1:
            ### Got something of the form `set x`; just print value of x. ###
            try:
                k = argv[0]
                v = self._debugger.get_conf(k)
                print("%s = %s" % (k, v))
            except KeyError as e:
                print(str(e))
        else:
            ### Received key and value (`set k v` or `set k=v`); update the config ###
            if len(argv) == 1 and len(argv[0].split("=", 1)) == 2:
                # Support `set k=v` format
                k = argv[0].split("=", 1)[0]
                v = argv[0].split("=", 1)[1]
            else:
                k = argv[0]
                start = 1
                if argv[start] == "=": # allow 'set x y' or 'set x = y' format.
                    start = start + 1
                v = " ".join(argv[start:])

            k = k.strip()
            v = v.strip()

            # We now have a single string for key (k) and a single string for value (v).
            # Convert user-input strings into the correct data types.
            # We support bool, int (dec and 0xHEX), and empty string as 'None'.
            if isinstance(v, str) and v.lower() == "true":
                v = True
            elif isinstance(v, str) and v.lower() == "false":
                v = False
            elif isinstance(v, str) and v == str(_softint(v)) and v != "None":
                v = int(v)
            elif isinstance(v, str) and v.startswith("0x") and len(v) > 2 and \
                    v == "0x" + str(_softint(v[2:], base=16)) and v != "0xNone":
                v = int(v[2:], base=16)
            elif isinstance(v, str) and len(v) == 0:
                v = None

            # Actually push this (k, v) pair to the debugger's config state.
            try:
                self._debugger.set_conf(k, v)
            except KeyError as e:
                print(str(e))


    @Command(keywords=['stack'])
    def _stack_display(self, argv):
        """
        Display memory from a range of addresses on the stack

            Syntax: stack [<length>] [<offset>]

        * length is in bytes; default is 16.
        * data printing starts at ($SP + offset).
        * If offset is omitted or -1, then "auto-skip" stack frames added by the debugger.
        """
        offset = -1 # auto
        length = 16
        if len(argv) == 1:
            length = int(argv[0])
        elif len(argv) > 1:
            length = int(argv[0])
            offset = int(argv[1])

        (sp, top, snapshot) = self._debugger.get_stack_snapshot(length, offset)
        length = len(snapshot)

        snapshot.reverse()
        highaddr = top + length - 1
        addr = highaddr
        offset = top - sp - 1
        ramend = self._debugger.get_arch_conf("RAMEND")
        is_at_ramend = addr == ramend
        print(f"$SP: {sp:#04x}  Top: {top:#04x}   skip: {offset}")
        for b in snapshot:
            print(f'{addr:04x}: {b:02x}')
            addr -= 1

        if not is_at_ramend:
            print(f'Next: stack 16 {length + offset}')


    @Command(keywords=['stackaddr', 'xs'], completions=[Completions.WORD_SIZE])
    def _stack_mem_read(self, argv):
        """
        Read an address relative to the $SP register

            Syntax: stackaddr [size] <offset (hex)>
        """
        if len(argv) == 0:
            print("Syntax: stackaddr [<size>] <offset (hex)>")
            return
        elif len(argv) == 1:
            size = 1
            offset = int(argv[0], base=16)
        else:
            size = int(argv[0])
            offset = int(argv[1], base=16)

        if size < 1:
            size = 1
        elif size > 4 or size == 3:
            size = 4

        v = self._debugger.get_stack_sram(offset, size)
        if size == 1:
            print(f"{v:02x}")
        elif size == 2:
            print(f"{v:04x}")
        elif size == 4:
            print(f"{v:08x}")


    @Command(keywords=['frame', '\\f'])
    def _frame(self, argv):
        """
        Display memory contents of a stack frame

            Syntax: frame <n>

        This function displays memory from the n'th stack frame. See the 'backtrace' command
        to get a list of available stack frames.
        """
        if len(argv) == 0:
            print("Syntax: frame <n> -- display memory from n'th stack frame")
            return
        else:
            frame_num = int(argv[0])

        frames = self._debugger.get_backtrace(limit=(frame_num + 1))
        if len(frames) <= frame_num:
            print(f"Error: could only identify {len(frames)} stack frames")
            return

        frame = frames[frame_num]
        sp = frame.sp
        frame_size = frame.frame_size
        if frame_size < 0:
            frame_size = 16
            print(f"Warning: could not identify size of stack frame. Defaulting to {frame_size}.")

        print(f'Frame {frame_num} at PC {frame.addr:#04x} in method {frame.demangled}')

        ret_addr_size = self._debugger.get_arch_conf("ret_addr_size")
        ret_addr = self._debugger.get_return_addr_from_stack(sp + frame_size + 1)
        ret_fn_sym = self._debugger.function_sym_by_pc(ret_addr)
        if ret_fn_sym:
            ret_fn = ret_fn_sym.demangled or ret_fn_sym.name
        else:
            ret_fn = '???'
        print(f'Frame {frame_num} size={frame_size}; return address: {ret_addr:#04x} in {ret_fn}')

        for addr in range(sp + frame_size, sp, -1):
            b = self._debugger.get_sram(addr, 1)
            print(f'{addr:04x}: {b:02x}')

        if frame_size == 0:
            addr = sp + frame_size + 1 # Ensure `addr` initialized in case frame_size == 0.

        print(f'{addr-1:04x} <-- $SP')

        registers = self._debugger.get_frame_regs(frame_num)
        if registers:
            print('\nRegisters:\n')
            self.__format_registers(registers)



    @Command(keywords=['time'], help_keywords=['tm','tu'], completions=[['millis', 'micros']])
    def _print_time(self, argv):
        """
        Read the time from the device in milli- or microseconds

            Syntax: time {millis|micros}

        Prints the time since start (or rollover) as reported by the device.
        """

        if len(argv) == 0:
            print("Syntax: time {millis|micros}")
            return

        if argv[0] == "millis":
            return self._print_time_millis(argv)
        elif argv[0] == "micros":
            return self._print_time_micros(argv)
        else:
            print("Syntax: time {millis|micros}")
            return


    @Command(keywords=['tm'], display_help=False)
    def _print_time_millis(self, argv):
        """
        Print time since device startup (or rollover) in milliseconds.
        """
        print(self._debugger.send_cmd(protocol.DBG_OP_TIME_MILLIS, self._debugger.RESULT_ONELINE))


    @Command(keywords=['tu'], display_help=False)
    def _print_time_micros(self, argv):
        """
        Print time since device startup (or rollover) in microseconds.
        """
        print(self._debugger.send_cmd(protocol.DBG_OP_TIME_MICROS, self._debugger.RESULT_ONELINE))


    @Command(keywords=['setv', '!'], completions=[Completions.SYM])
    def _set_var(self, argv):
        """
        Update the value of a global variable

            Syntax: setv <symbol_name> [=] <value> [base=10]"

        e.g. if you have `uint_8t my_global = 40;` in your sketch, you can change this with:
          setv my_global = 99
        ... and set it back with:
          setv my_global = 40

        After applying a 'setv' command, the shorthand '$' will refer to the last symbol used.
        See also: 'print <symbol_name>' to read the value of a variable in RAM.
        """
        base = 10
        hwm = 0 # high-water mark for tokens consumed
        if len(argv) == 0:
            print("Syntax: setv <symbol_name> [=] <value> [base=10]")
            return
        elif len(argv[0].split("=", 1)) == 2:
            # setv sym=val [base]
            name = argv[0].split("=", 1)[0]
            val = argv[0].split("=", 1)[1]
            hwm = 1
        elif len(argv) >= 2:
            name = argv[0]
            if argv[1] == "=" and len(argv) >= 3:
                # setv sym = val [base]
                val = argv[2]
                hwm = 3
            else:
                # setv sym val [base]
                val = argv[1]
                hwm = 2
        else:
            # len(argv) = 1 but no equality; just 'setv sym'.
            print("Syntax: setv <symbol_name> [=] <value> [base]")
            return

        if hwm < len(argv):
            try:
                base = int(argv[hwm])
            except ValueError:
                print(f"Warning: could not set base={argv[hwm]}. Using base 10")
                base = 10


        sym = self._debugger.lookup_sym(name)
        if sym is None:
            print(f"No symbol found: {name}")
            return

        self._last_sym_used = name # Symbol argument saved as last symbol used.

        # Convert argument to integer. (TODO(aaron): Handle floating point some day?)
        try:
            val = int(val, base=base)
        except ValueError:
            print(f"Error: Cannot parse integer value {val} in base {base}")
            return

        # Resolve symbol to memory address
        addr = sym.addr
        size = 1 # set default...
        try:
            size = sym.size # override if available.
        except KeyError:
            pass

        if size < 1:
            size = 1
        elif size > 4 or size == 3:
            size = 4

        data_addr_mask = self._debugger.get_arch_conf("DATA_ADDR_MASK")
        if data_addr_mask and (addr & data_addr_mask) == addr:
            # We're trying to update something in flash.
            print(f"Error: Cannot write to flash segment at address {addr:x}")
        else:
            # We're trying to update something in SRAM:
            self._debugger.set_sram(addr, val, size)


    @Command(keywords=['sym', "?"])
    def _symbol_search(self, argv):
        """
        Look up symbols containing a substring

            Syntax: sym <symbol_substr>

        This is especially useful for hunting for a mangled C++ symbol.
        e.g., try: sym print

        This command returns a list of symbols matching /.*<substr>.*/. This list contains
        both plain (mangled) and demangled names, which are synonyms for the same memory
        address.

        The result of this search is cached; you can use #n anyplace you can use a symbol
        as an argument to refer to the n'th list item from the last 'sym' search.

        e.g.:
          sym foo
          setv #0 42
        (Assuming the first returned entry is a variable named something like '_foo', sets its value
        to 42.)

        If this search returns a unique symbol name, you can refer to that symbol using
        the shorthand '$'. e.g.:
          (agdb) sym foo
          my_foo
          (agdb) print $
          0012ab34
        ... will print the value in memory of the unique result for the /.*foo.*/ search.

        Thereafter, '$' will refer to the most recently-used symbol in print, setv, etc.

        If one of the returned symbols is an exact match for the search, it is flagged with '(**)'.
        """
        if len(argv) == 0:
            print("Syntax: sym <substring>")
            return

        # Perform the symbol search and also cache it.
        self._last_sym_search = self._debugger.syms_by_substr(argv[0])
        if len(self._last_sym_search) == 0:
            print("(No matching symbols)")
        elif len(self._last_sym_search) == 1:
            # Found a unique hit.
            print(self._last_sym_search[0])
            self._last_sym_used = self._last_sym_search[0] # last-used symbol is the unique match.
        else:
            # Multiple results
            for i in range(0, len(self._last_sym_search)):
                this_sym = self._last_sym_search[i]
                if this_sym == argv[0]:
                    # Exact match
                    asterisk = "(**)  "
                else:
                    asterisk = ""

                print(f"#{i}. {asterisk}{this_sym}")


    @Command(keywords=['syms'])
    def _list_symbols(self, argv):
        """
        List all symbols
        """
        all_syms = self._debugger.syms_by_substr("")
        if len(all_syms) == 0:
            print("No symbol information available")
            return

        for i in range(0, len(all_syms)):
            print(f"#{i}. {all_syms[i]}")


    @Command(keywords=['types'])
    def _list_types(self, argv):
        """
        List all defined datatypes
        """

        for (name, typ) in types.types():
            print(typ)

    @Command(keywords=['addr', '.'], completions=[Completions.SYM])
    def _addr_for_sym(self, argv):
        """
        Show address of a symbol

            Syntax: addr <symbol_name>

        See also: the 'sym' command - search for a precise symbol name via substring.
        After a search with 'sym', you can use #0 (or '$'), #1, #2... to refer to results.
        """
        if len(argv) == 0:
            print("Syntax: addr <symbol_name>")
            return

        sym = self._debugger.lookup_sym(argv[0])
        if sym is None:
            print(f"No symbol found: {argv[0]}")
            print(f"(Try 'sym {argv[0]}')")
            return

        print(f'{sym.demangled}: {sym.addr:08x} ({sym.size})')
        self._last_sym_used = argv[0] # Looked-up symbol is last symbol used.


    @Command(keywords=['type'], completions=[Completions.SYM_OR_TYPE])
    def _sym_datatype(self, argv):
        """
        Show datatype for symbol or type name

            Syntax: type <name>
        """
        if len(argv) == 0:
            print("Syntax: type <name>")
            return

        registers = self._debugger.get_registers()
        pc = registers["PC"]
        sym = argv[0]
        (kind, typ) = types.getNamedDebugInfoEntry(sym, pc)
        if kind is None:
            print(f'{sym}: <unknown type>')
        elif kind == types.KIND_TYPE or kind == types.KIND_METHOD:
            # Print the type description directly, or print the method signature (which includes
            # the method name) directly
            print(f'{typ}')
        else:
            # kind == types.VARIABLE
            print(f'{sym}: {typ.name}')

        return kind

    @Command(keywords=['info', '\\i'], completions=[Completions.SYM])
    def _sym_info(self, argv):
        """
        Show info about a symbol: type, addr, value

            Syntax: info <symbol_name>

        This is equivalent to running the 'type', 'addr', and 'print' commands with the same
        symbol name as the argument to each.
        """
        if len(argv) == 0:
            print("Syntax: info <symbol_name>")
            return

        kind = self._sym_datatype(argv)
        if kind != types.KIND_TYPE:
            # For methods and variables, show the address
            self._addr_for_sym(argv)
        if kind == types.KIND_VARIABLE:
            # For variables, show the memory value at that address
            self._print(argv)


    @Command(keywords=['help'], completions=[Completions.KW])
    def print_help(self, argv):
        """
        Print usage information

        Syntax: help [cmd]

        If given a specific command name, will print the usage info for that command.
        Otherwise, this help message lists all available commands.
        """

        if len(argv) > 0:
            try:
                cmd = argv[0]
                cmdMap = Command.getCommandMap()
                cmdObj = cmdMap[cmd]
                print(cmdObj.long_help)
            except:
                print(f"Error: No command {argv[0]} found.")
                print("Try 'help' to list all available commands.")
                print("Use 'quit' to exit the debugger.")

            return

        print("Commands")
        print("--------")

        cmdIndex = Command.getCommandIndex()
        for (keyword, cmdObj) in cmdIndex.items(): # iterate over sorted map.
            if cmdObj.display_help:
                print(cmdObj.short_help)

        print("")
        print("After doing a symbol search with sym or '?', you can reference results by")
        print("number, e.g.: `print #3`  // look up value of 3rd symbol in the list")
        print("The most recently-used such number--or '#0' if '?' gave a unique result--can")
        print("then be referenced as '$'. e.g.: `print $`  // look up the same value again")
        print("")
        print("For more information, type: help <command>")


    @Command(keywords=['quit', '\\q'])
    def _quit(self, argv):
        """
        Quit the debugger console
        """
        # This method does not actually quit -- that is behavior hardcoded into the REPL.
        # However, having this method in the _cmd_map enables its docstring to be used for
        # `help quit`.
        pass

    def loop_input_body(self):
        """
            Primary function to call inside a loop; executes one flow of Read-eval-print.
            Returns True if we want to quit, False to continue.
        """
        commandMap = Command.getCommandMap()

        try:
            cmdline = input("(adbg) ")
        except KeyboardInterrupt:
            # Received '^C'; call the break function
            print('') # Terminate line after visible '^C' in input.
            self._break()
            self._break_count += 1
            if self._break_count >= 3:
                # User's mashed ^C a lot... try to help them out?
                print("Use 'quit' to exit the debugger.")
                print("Try 'help' to list all available commands.")
                self._break_count = 0

            return False
        except EOFError:
            # Received '^D'; time to quit
            print('')
            return True

        self._break_count = 0 # User typed a real non-^C command.

        raw_tokens = cmdline.split(" ")
        tokens = []
        for t in raw_tokens: # Filter extra empty-whitespace tokens
            if t == "$":
                if self._last_sym_used:
                    # Replace '$' with last-referenced symbol.
                    tokens.append(self._last_sym_used)
                else:
                    print("Warning: no prior symbol reference for '$'")
                    tokens.append("$") # try it raw...
            elif isinstance(t, str) and t.startswith("#") and len(t) > 1 and t[1:] == str(_softint(t[1:])):
                idx = _softint(t[1:])
                try:
                    # replace '#n' with n'th item in last symbol search.
                    sym = self._last_sym_search[idx]
                    tokens.append(sym)
                except IndexError:
                    print(f"Warning: no symbol for index {t}")
                    tokens.append(t) # try it raw...
            elif t is not None and t != "":
                tokens.append(t)

        if len(tokens) == 0:
            return False

        cmd = tokens[0]

        if cmd == "quit" or cmd == "exit" or cmd == "\\q":
            return True # Actually quit.
        elif cmd in commandMap.keys():
            try:
                cmd_obj = commandMap[cmd]
                cmd_obj.invoke(self, tokens[1:])
            except Exception as e:
                print(f"Error running '{cmd}': {e}")
                if self._debugger.get_conf("dbg.verbose"):
                    traceback.print_tb(e.__traceback__)
                else:
                    print("For stack trace info, `set dbg.verbose True`")
        else:
            print("Unknown command '%s'; try 'help'." % cmd)

        return False


    def loop(self):
        """
            The actual main loop.

            Returns the exit status for the program. (0 for success)
        """
        readline.parse_and_bind('set editing-mode vi')
        readline.parse_and_bind('tab: complete')
        completer = ReplAutoComplete(self._debugger)
        readline.set_completer(completer.complete)

        quit = False
        while not quit:
            if self._debugger.process_state() == dbg.PROCESS_STATE_BREAK:
                # Program execution is paused; we accept commands from the user.
                quit = self.loop_input_body()
            else:
                # The program is (maybe?) running. It could send debug/trace messages back,
                # so we sit and wait for those and display them if/when they appear.
                print("Press ^C to interrupt Arduino sketch for debugging.")
                try:
                    self._debugger.wait_for_traces()
                except KeyboardInterrupt as ki:
                    # Received '^C'; call the break function
                    print('') # Terminate line after visible '^C' in input.
                    self._break() # This will update the process_state to BREAK.

        return 0


