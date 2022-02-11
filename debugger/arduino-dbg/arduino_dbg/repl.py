# (c) Copyright 2021 Aaron Kimball

import functools
import os
import os.path
import readline
import signal
import traceback

import arduino_dbg
import arduino_dbg.debugger as dbg
import arduino_dbg.dump as dump
import arduino_dbg.eval_location as el
import arduino_dbg.io as io
import arduino_dbg.memory_map as memory_map
import arduino_dbg.protocol as protocol
from arduino_dbg.repl_command import Completions, Command, CompoundCommand, ReplAutoComplete, \
    repl_split, print_command_help
import arduino_dbg.term as term
from arduino_dbg.term import MsgLevel
import arduino_dbg.types as types
import arduino_dbg.version

PROMPT = term.PROMPT


def _softint(intstr, base=10):
    """
        Try to convert intstr to an int; if it fails, return None instead of ValueError like int()
    """
    try:
        return int(intstr, base)
    except ValueError:
        return None


class Repl(object):
    """
    The interactive command-line the user interacts with directly.
    """

    def __init__(self, debugger, console_printer, hosted_dbg_service=None):
        self._debugger = debugger
        self._console_printer = console_printer
        self._hosted_dbg_service = hosted_dbg_service

        signal.signal(signal.SIGINT, signal.default_int_handler)

        self._last_sym_search = []   # results of most-recent symbol substr search.
        self._last_sym_used = None   # last symbol referenced by the user.

        self._break_count = 0  # How many times has the user mashed ^C?

        self._completer = ReplAutoComplete(self._debugger)
        readline.parse_and_bind('set editing-mode vi')
        readline.parse_and_bind('set bell-style none')
        readline.parse_and_bind('tab: complete')
        readline.set_completer_delims(" \t\r\n'\"")  # We want chunkier tokens than RL default.
        readline.set_completer(self._completer.complete)

        # load history from file as indicated in debugger conf and monitor debugger conf for changes
        # to user-configured filename.
        self._history_filename = None
        debugger.set_history_change_hook(self._history_change_callback)

    def debugger(self):
        return self._debugger

    def close(self):
        if self._hosted_dbg_service:
            self._hosted_dbg_service.shutdown()

        if self._debugger:
            self._debugger.close()

        self._console_printer.shutdown()

        self._hosted_dbg_service = None
        self._debugger = None
        self._console_printer = None

    def _history_change_callback(self, filename):
        """
        Callback method for Debugger to invoke if the config'd history filename changes.
        """
        filename = os.path.normpath(filename)

        if filename == self._history_filename and (filename is None or os.path.exists(filename)):
            # We got a redundant update; filename hasn't changed, and we have no work to do
            # in the form of ensuring the history file exists for appending-to. Debounce signal.
            return

        self._history_filename = filename
        if os.path.exists(filename):
            readline.read_history_file(filename)
            self._debugger.verboseprint(f"Loaded history from file: {filename}")
        else:
            self._debugger.verboseprint(f"Creating new history file: {filename}")
            f = open(filename, 'w')
            f.close()

    def _append_history(self):
        if self._history_filename is not None:
            try:
                readline.append_history_file(1, self._history_filename)
            except Exception as e:
                self._debugger.msg_q(
                    MsgLevel.WARN,
                    f'Error writing to history file: {e}. Disabling history file recording.')
                self._debugger.msg_q(
                    MsgLevel.WARN,
                    f'You can try a new file with: set dbg.historyfile = <filename>')
                self._history_filename = None

    def _format_local(self, frame, frameRegs, var_or_formal_lst, is_formal):
        """
        Resolve and format a local variable or formal method arg for printing.

        @param frame relevant stack.CallFrame
        @param frameRegs register values within the CallFrame
        @param var_or_formal_lst a non-empty list of VariableInfo or FormalArg elements with the
            same name; we try these in order and print the value of the first we can locate.
        @param is_formal true if the list is FormalArgs; false for VariableInfos.
        """
        assert isinstance(var_or_formal_lst, list)
        assert len(var_or_formal_lst) > 0

        best_flags = None
        best_val = None
        best_var = None
        for var_or_formal in var_or_formal_lst:
            local_val, flags = var_or_formal.getValue(frameRegs, frame)
            if el.LookupFlags.successful(flags):
                if best_flags is None:
                    # Hooray! We converged on a value.
                    best_val = local_val
                    best_flags = flags
                    best_var = var_or_formal
                elif el.LookupFlags.has_warnings(best_flags) and not el.LookupFlags.has_warnings(flags):
                    # We converged on a value calculated w/o any warnings. Supercedes prior result.
                    best_val = local_val
                    best_flags = flags
                    best_var = var_or_formal
                else:
                    # We got a value w/ warnings, but we already had one of those.
                    # Not necessarily any better.
                    pass

                if not el.LookupFlags.has_warnings(flags):
                    # There's no reason to keep calculating any further; we got a successful
                    # no-warning result, so that's what we'll use.
                    break
            elif flags & el.LookupFlags.ERR_PC_OUT_OF_BOUNDS:
                best_flags = flags  # We'd rather report PC_OUT_OF_BOUNDS than NO_LOCATION.
                                    # The former simply means "not valid at this breakpoint" vs
                                    # "this VariableInfo is useless".
                best_val = None
                best_var = var_or_formal
            elif best_flags is None:
                best_flags = flags  # Whatever error we got, let's track that.
                best_val = None
                best_var = var_or_formal

        # At this point either we hit a 'break' and have a successful value and flags,
        # or we have a value and warning flags, or no value and error flags.
        # Whatever that outcome is, it's in best_val / best_flags and the associated FormalArg or
        # VariableInfo is in best_var.
        assert best_var is not None
        assert best_flags is not None
        self._console_printer.join_q()  # sync printer after doing all the eval_location work.

        if is_formal:
            assert isinstance(best_var, types.FormalArg)
            local_type = best_var.arg_type
        else:
            assert isinstance(best_var, types.VariableInfo)
            local_type = best_var.var_type

        assert local_type is not None

        val_str = el.format_accessed_val(best_val, local_type)
        type_name = f'{local_type.name}'

        if best_var.name is not None:
            name_and_type = f'{best_var.name}: {type_name}'
        else:
            name_and_type = f'({type_name})'

        # Format any warning messages and colorize appropriately.
        warnings = el.LookupFlags.get_message(best_flags)
        if el.LookupFlags.has_warnings(best_flags):
            warn_color = term.WARN
            val_color = term.WARN
        elif el.LookupFlags.has_errors(best_flags):
            warn_color = term.ERR
            val_color = term.ERR
        else:
            warn_color = term.INFO
            val_color = term.BOLD
        warnings = term.fmt(warnings, warn_color)
        val_str = term.fmt(val_str, val_color)
        if len(val_str):
            val_str = " = " + val_str

        out_str = f'{name_and_type}{val_str} {warnings}'
        return out_str


    def __get_scoped_locals(self, frameScopes):
        """
        Walk through nested frameScopes and gather formals and variables from the current
        method as well as any LexicalScope descendants that aren't part of a further nested
        (inlined) method.

        Return a dict that contains 'locals', 'formals', 'scope' and 'next' - a linked-list ptr to the
        next nested dict.
        * locals is a list of lists; each sub-list is VariableInfos with the same name. The outer
          list is sorted in alpha order. Inner lists are sorted by increasing $PC - earlier
          definitions come first.
        * formals is a list of lists; each sub-list is FormalArgs with the same name. The outer list
          is sorted in method call order. Inner lists are soretd by increasing $PC like locals.
        * scope is the MethodInfo.

        Returns None if frameScopes is None or an empty list.
        """

        if frameScopes is None or len(frameScopes) == 0:
            return None

        nested_methods = {'next': None}  # Create a linked list of containers for vars/formals.
        cur = None

        def __add_to_locals(locals_list, var, var_name):
            """
            Helper method for use in the loop below.

            locals_list is one of cur['formals'] or cur['locals'] - a list of lists of
            identically-named vars.

            'var' is the formal/local to either add as a new list entry, or
            append to a sublist of other identically-named entries.
            """
            found_idx = None
            for cur_idx in range(0, len(locals_list)):
                item_list = locals_list[cur_idx]
                if len(item_list) and item_list[0].name == var_name:
                    found_idx = cur_idx  # We found a list of formals/locals w/ the same name
                    break

            if found_idx is not None:
                locals_list[found_idx].append(var)  # append to identically-named list.
            else:
                locals_list.append([var])  # Start a new list

        for scope in frameScopes:
            if isinstance(scope, types.MethodInfo):
                if cur is None:
                    cur = nested_methods  # Use first scope
                else:
                    # New nested inline method. Create a new nested scope.
                    new_method = {'next': None}
                    cur['next'] = new_method
                    cur = new_method

                # Initialize the new scope.

                # Each of these lists contains *lists* of FormalArgs or VariableInfos. All
                # args/infos with the same `name` field are in the same list. They are ordered
                # widest-scope to narrowest.  Only one arg/info per list will be presented to the
                # user; we choose the narrowest-scope definition with a valid location, or if none
                # have a valid location, report that fact once.
                cur['formals'] = []
                cur['locals'] = []
                cur['scope'] = scope
            elif isinstance(scope, types.LexicalScope):
                # Stay within current nested_method. Add formals/locals to the 'cur' that represents
                # the containing method.
                if cur is None:
                    raise Exception("Unexpected: LexicalScope w/o containing MethodInfo")


            for formal in scope.getFormals():
                name = formal.name
                if name is None:
                    # Type-only formals are always singleton lists that honor arg order position.
                    cur['formals'].append([formal])
                else:
                    # Check if any other formals encountered thus far in the method scope
                    # have the same name as the current one.
                    __add_to_locals(cur['formals'], formal, name)

            for name, local_var in scope.getVariables():
                if name is None:
                    # We don't bother with anonymous local vars; (phantom entries?)
                    continue
                __add_to_locals(cur['locals'], local_var, name)

            # Sort the locals by alphabetical order of names.
            # Each sublist is guaranteed by the code above to be non-empty. Locals in the list are
            # guaranteed to have non-empty names.
            # (We do not sort formals; we rely on their initial ordering to present them to the user
            # in method signature order.)
            cur['locals'].sort(key=lambda var_list: var_list[0].name)

        return nested_methods

    @Command(keywords=['locals'])
    def _show_locals(self, argv):
        """
        Show info about local variables in a stack frame

            Syntax: locals <frame>

        Given a frame number (from a `backtrace` command), show info about local variables
        within the method scope at the current $PC.
        """
        if len(argv) == 0:
            self._debugger.msg_q(MsgLevel.INFO, "Syntax: locals <frame>")
            return

        frameId = int(argv[0])
        frame = self.__get_frame(frameId)
        frameScopes = self._debugger.get_frame_vars(frameId)
        frameRegs = self._debugger.get_frame_regs(frameId)
        if frameScopes is None:
            self._debugger.msg_q(MsgLevel.INFO, f'No such stack frame {frameId}')
            return

        nested_methods = self.__get_scoped_locals(frameScopes)
        if nested_methods is None:
            self._debugger.msg_q(MsgLevel.INFO, f'Empty stack frame?')
            return

        # nested_methods now contains a linked list of formal/local lists and corresponding
        # MethodInfo entries. Each formal/local is represented by a list of one or more FormalArg
        # or VariableInfo entries encountered w/ the same name.
        # (TODO(aaron): Do we ever encounter globals in here, that alias a local?)
        nest = 0
        cur = nested_methods
        while cur is not None:
            nest_str = nest * ' '
            scope = cur['scope']  # Relevant MethodInfo
            printed_formals = False
            if not scope.is_decl and not scope.is_def:
                inl_str = 'Inlined method'
            else:
                inl_str = 'Method'
            self._debugger.msg_q(
                MsgLevel.INFO,
                f'{nest_str}{inl_str} scope: {scope.make_signature(include_class=True)}')
            die = scope.get_die()
            if die is not None:
                self._debugger.verboseprint(
                    nest_str, 'Method DIE at offset 0x',
                    dbg.VHEX4, die.offset)

            formals = cur['formals']
            if len(formals) > 0:
                printed_formals = True
                self._debugger.msg_q(MsgLevel.INFO, f"{nest_str}  Formals:")
                for formal_lst in formals:
                    # formal_lst contains a list of FormalArg entries w/ the same name.
                    formal_lst.reverse()  # re-sort so its narrowest scope def first.
                    local_str = self._format_local(frame, frameRegs, formal_lst, is_formal=True)
                    self._debugger.msg_q(MsgLevel.INFO, f'{nest_str}  {local_str}')

            locals_list = cur['locals']
            if len(locals_list) > 0:
                if printed_formals:
                    self._debugger.msg_q(MsgLevel.INFO, '')

                self._debugger.msg_q(MsgLevel.INFO, f"{nest_str}  Locals:")
                for local_var_lst in locals_list:
                    # local_var_lst contains a list of VariableInfo entries w/ the same name
                    local_var_lst.reverse()  # re-sort so its narrowest scope def first.
                    local_str = self._format_local(frame, frameRegs, local_var_lst, is_formal=False)
                    self._debugger.msg_q(MsgLevel.INFO, f'{nest_str}  {local_str}')

            cur = cur['next']  # advance linked list ptr.
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
            self._debugger.msg_q(MsgLevel.INFO, f"{i}. {frames[i]}")


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

    @Command(keywords=['file'], completions=[Completions.PATH])
    def _read_elf(self, argv):
        """
        Read symbol and type information from an ELF file

            Syntax: file <filename.elf>

        Purges information from any previously-loaded ELF file.
        """
        if len(argv) == 0:
            self._debugger.msg_q(MsgLevel.INFO, "Syntax: file <filename.elf>")
            return

        filename = argv[0]
        self._debugger.replace_elf_file(filename)


    @Command(keywords=['open'])
    def _open(self, argv):
        """
        Open serial connection to a device to debug

            Syntax: open </dev/ttyname> [<baud>]

        If baud rate is not specified, attempts to use 57600.
        """
        if len(argv) == 0:
            self._debugger.msg_q(MsgLevel.INFO, "Syntax: open </dev/ttyname> [<baud>]")
            return

        port = argv[0]
        if len(argv) > 1:
            baud = argv[1]
        else:
            baud = 57600

        connection = io.SerialConn(port, baud, 0.1)
        self._debugger.open(connection)

    @Command(keywords=['reopen'])
    def _reopen(self, argv):
        """
        Reestablish the serial connection to the current port

            Syntax: reopen

        To change connection parameters, use the `open` command.
        """
        self._debugger.reconnect()

    @Command(keywords=['flash', 'xf'], completions=[Completions.WORD_SIZE])
    def _flash(self, argv):
        """
        Read a flash address on the Arduino

            Syntax: flash [<size>] <addr (hex)>

        size must be 1, 2, or 4. Address must be in base 16 (hex).
        """

        if len(argv) == 0:
            self._debugger.msg_q(MsgLevel.INFO, "Syntax: flash [<size>] <addr (hex)>")
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
        self._debugger.msg_q(MsgLevel.INFO, f"<{v}>")
        if size == 1:
            self._debugger.msg_q(MsgLevel.INFO, f"{v:02x}")
        elif size == 2:
            self._debugger.msg_q(MsgLevel.INFO, f"{v:04x}")
        elif size == 4:
            self._debugger.msg_q(MsgLevel.INFO, f"{v:08x}")

    @Command(keywords=['gpio'], completions=[Completions.NONE, Completions.BINARY])
    def _gpio(self, argv):
        """
        Read or write a GPIO pin

            Syntax: gpio <pinId> [<value>]

        This command can only write to pins already configured as outputs.
        """

        if len(argv) == 0:
            self._debugger.msg_q(MsgLevel.INFO, "Syntax: gpio <pinId> [<value>]")
            return
        elif len(argv) == 1:
            try:
                pin = int(argv[0])
            except ValueError:
                self._debugger.msg_q(MsgLevel.ERR, f"Error: could not parse pin id {argv[0]}")
                return

            num_pins = self._debugger.get_platform_conf("gpio_pins")
            if pin < 0 or pin >= num_pins:
                self._debugger.msg_q(
                    MsgLevel.ERR,
                    f"Error: available gpio pins are between [0, {num_pins}).")

            v = self._debugger.get_gpio_value(pin)
            if v is not None:
                self._debugger.msg_q(MsgLevel.INFO, v)
        else:
            # 2+ args => set the pin value.
            try:
                pin = int(argv[0])
            except ValueError:
                self._debugger.msg_q(MsgLevel.ERR, f"Error: could not parse pin id {argv[0]}")
                return

            try:
                val = int(argv[1])
            except ValueError:
                self._debugger.msg_q(MsgLevel.ERR, f"Error: could not parse value ({argv[1]})")
                return

            if val != 0 and val != 1:
                self._debugger.msg_q(MsgLevel.ERR, "Error: value must be 0 or 1")
                return

            num_pins = self._debugger.get_platform_conf("gpio_pins")
            if pin < 0 or pin >= num_pins:
                self._debugger.msg_q(
                    MsgLevel.ERR,
                    f"Error: available gpio pins are between [0, {num_pins}).")

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
        if self._debugger.get_arch_conf('stack_model') == 'full_desc':
            # Arithmetic above is based on empty-descending stack model (as in AVR);
            # off by 1 for full-descending stacks like ARM.
            stack_size += 1

        if mem_map["HeapEnd"] != 0:
            heap_size = mem_map["HeapEnd"] - mem_map["HeapStart"]
        else:
            heap_size = 0  # No allocation performed

        global_size = mem_map["HeapStart"] - ram_start
        free_ram = total_ram - stack_size - heap_size - global_size

        self._debugger.msg_q(
            MsgLevel.INFO,
            f'   Total RAM:  {total_ram:>8}  RAMEND={ram_end:04x} .. RAMSTART={ram_start:04x}')
        self._debugger.msg_q(
            MsgLevel.INFO,
            f'  Stack size:  {stack_size:>8}      SP={mem_map["SP"]:04x}')
        self._debugger.msg_q(MsgLevel.INFO, f'      (free):  {free_ram:>8}')
        self._debugger.msg_q(MsgLevel.INFO, f'   Heap size:  {heap_size:>8}')
        self._debugger.msg_q(MsgLevel.INFO, f'     Globals:  {global_size:>8} (.data + .bss)')
        self._debugger.msg_q(MsgLevel.INFO, f'     Globals:  {global_size:>8} (.data + .bss)')
        self._debugger.msg_q(MsgLevel.INFO, f'')
        self._debugger.msg_q(MsgLevel.INFO, repr(self._debugger.arch_iface.memory_map()))



    @Command(keywords=['mem', 'x', '\\m'], completions=[Completions.WORD_SIZE])
    def _mem(self, argv):
        """
        Read a memory address on the Arduino

            Syntax: mem [<size>] <addr (hex)>

        On a segmented memory system, you must provide a logical address, not a physical in-segment
        memory address to write. On AVR, SRAM addresses begin at 0x800000.

        size must be 1, 2, or 4.
        """
        if len(argv) == 0:
            self._debugger.msg_q(MsgLevel.INFO, "Syntax: mem [<size>] <addr (hex)>")
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

        # Resolve logical address to physical address.
        mmap = self._debugger.arch_iface.memory_map()
        phys_addr = mmap.logical_to_physical_addr(addr)
        if mmap.access_mechanism_for_addr(addr) == memory_map.ACCESS_TYPE_PGM:
            # We're trying to read something in flash with 'mem'.
            self._debugger.msg_q(
                MsgLevel.ERR,
                f"Error: Cannot read flash segment at address {addr:x} with 'mem'; try 'flash'.")

        v = self._debugger.get_sram(phys_addr, size)
        if size == 1:
            self._debugger.msg_q(MsgLevel.INFO, f"{v:02x}")
        elif size == 2:
            self._debugger.msg_q(MsgLevel.INFO, f"{v:04x}")
        elif size == 4:
            self._debugger.msg_q(MsgLevel.INFO, f"{v:08x}")


    @Command(
        keywords=['poke'],
        completions=[Completions.NONE, Completions.NONE, Completions.WORD_SIZE, Completions.BASE])
    def _poke(self, argv):
        """
        Write to a variable or memory address on the Arduino

            Syntax: poke <addr (hex)> <value> [size=1] [base=10]

        This will write to any address in the Arduino's SRAM and can easily corrupt your program.
        To set the value of a global variable with a known symbol, see the `setv` command.

        On a segmented memory system, you must provide a logical address, not a physical in-segment
        memory address to write. On AVR, SRAM addresses begin at 0x800000.
        """
        base = 10
        if len(argv) < 2:
            self._debugger.msg_q(MsgLevel.INFO, "Syntax: poke <addr (hex)> <value> [size=1] [base=10]")
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
                self._debugger.msg_q(
                    MsgLevel.WARN,
                    f"Warning: could not set base={argv[3]}. Using base 10")
                base = 10

        # Convert argument to integer. (TODO(aaron): Handle floating point some day?)
        try:
            val = int(val, base=base)
        except ValueError:
            self._debugger.msg_q(
                MsgLevel.ERR,
                f"Error: Cannot parse integer value {val} in base {base}")
            return

        # Resolve memory address
        try:
            addr = int(addr, base=16)
        except ValueError:
            self._debugger.msg_q(
                MsgLevel.ERR,
                f"Error: Cannot parse memory address {addr} in base 16")
            return

        # Resolve size
        try:
            size = int(size)
        except ValueError:
            self._debugger.msg_q(MsgLevel.ERR, f"Error: Cannot parse memory size {size}")

        if size < 1:
            size = 1
        elif size > 4 or size == 3:
            size = 4

        # Resolve logical address to physical address.
        mmap = self.arch_iface.memory_map()
        phys_addr = mmap.logical_to_physical_addr(addr)
        if mmap.access_mechanism_for_addr(addr) == memory_map.ACCESS_TYPE_PGM:
            # We're trying to update something in flash.
            self._debugger.msg_q(
                MsgLevel.ERR,
                f"Error: Cannot write to flash segment at address {addr:x}")
        else:
            # We're trying to update something in SRAM:
            self._debugger.set_sram(phys_addr, val, size)


    @Command(keywords=['print', 'v', '\\v'], completions=[Completions.SYM])
    def _print(self, argv):
        """
        Print a global variable's value

            Syntax: print <symbol_name>

        After applying a 'print' command, the shorthand '$' will refer to the last symbol used.
        See also the 'setv' command to change the value of a symbol in RAM.
        """
        if len(argv) == 0:
            self._debugger.msg_q(MsgLevel.INFO, "Syntax: print <symbol_name>")
            return

        sym = self._debugger.lookup_sym(argv[0])
        if sym is None:
            self._debugger.msg_q(MsgLevel.WARN, f"No symbol found: {argv[0]}")
            return

        self._last_sym_used = argv[0]  # Symbol argument saved as last symbol used.

        addr = sym.addr
        if sym.type_info:
            # Perform type-aware memory access and pretty-print result
            mem = el.Memory(self._debugger)
            if isinstance(sym.type_info, types.VariableInfo):
                val_type = sym.type_info.var_type
            else:
                val_type = sym.type_info
            val, flags = mem.access_address(addr, val_type, is_flat_address=True)
            self._debugger.msg_q(MsgLevel.INFO, el.format_accessed_val(val, sym.type_info))
        else:
            # No type information. Just print raw read as hex-formatted int.
            size = 1  # set default...
            try:
                size = sym.size  # override if available.
            except KeyError:
                pass

            if size < 1:
                size = 1
            elif size > 4 or size == 3:
                size = 4

            mmap = self.arch_iface.memory_map()
            phys_addr = mmap.logical_to_physical_addr(addr)
            if mmap.access_mechanism_for_addr(addr) == memory_map.ACCESS_TYPE_PGM:
                # We're requesting something in flash.
                v = self._debugger.get_flash(phys_addr, size)
            else:
                # We're requesting something in SRAM:
                v = self._debugger.get_sram(phys_addr, size)

            if size == 1:
                self._debugger.msg_q(MsgLevel.INFO, f"0x{v:02x}")
            elif size == 2:
                self._debugger.msg_q(MsgLevel.INFO, f"0x{v:04x}")
            elif size == 4:
                self._debugger.msg_q(MsgLevel.INFO, f"0x{v:08x}")


    def __format_registers(self, registers):
        """
        Actually format and print register values to the screen, for _regs() or _frame().
        """
        int_width = self._debugger.arch_iface.reg_width_bytes()
        sp_width = self._debugger.arch_iface.sp_width_bytes()  # [AVR] $SP may be extra-wide.
        self._debugger.msg_q(MsgLevel.INFO, term.fmt_registers(registers, int_width, sp_width))

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
        self._debugger.msg_q(MsgLevel.INFO, "Resetting sketch...")
        self._debugger.reset_sketch()
        if len(self._debugger.breakpoints().breakpoints()) > 0:
            self._debugger.msg_q(
                MsgLevel.INFO,
                "Disabled breakpoints will be reset. You may want to run `breakpoint sync`.")



    @Command(keywords=['set'], completions=[Completions.CONF_KEY])
    def _set_conf(self, argv):
        """
        Set or retrieve a config variable of the debugger

            Syntax: set [keyname [[=] value]]

        * If called with no arguments, this prints the entire config to stdout.
        * If called with just a setting name ("set foo"), print the setting value.
        * If called with "set keyname val", "set keyname = val", or "set keyname=val" then it
          updates the configuration with that value. If numeric, 'val' is assumed to be in
          base 10 unless it is prefixed with "0x".
        * If called with "set keyname =", will unset the setting (set it to None).

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
                items = [_fmt_value(v2, in_hex, True, level+1) for v2 in v]

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
                    items.append(
                        f"{_fmt_value(k2, in_hex2, True, level+1)}: "
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
            in_hex = isinstance(k, str) and k == k.upper()  # CAPS keys are printed in hex.
            self._debugger.msg_q(MsgLevel.INFO, f"{k} = {_fmt_value(v, in_hex)}")


        if len(argv) == 0:
            ### No key argument -- display entire configuration ###
            self._debugger.msg_q(MsgLevel.INFO, "Configurable debugger settings:")
            self._debugger.msg_q(MsgLevel.INFO, "-------------------------------")
            for (k, v) in self._debugger.get_full_config():
                _print_kv_pair(k, v)

            self._debugger.msg_q(MsgLevel.INFO, "")
            self._debugger.msg_q(MsgLevel.INFO, "Arduino platform configuration:")
            self._debugger.msg_q(MsgLevel.INFO, "-------------------------------")
            platform = self._debugger.get_full_platform_config()
            if len(platform) == 0:
                self._debugger.msg_q(
                    MsgLevel.WARN,
                    "No platform set; configure with 'set arduino.platform ...'.")
                self._debugger.msg_q(
                    MsgLevel.WARN, "See 'list platforms' for available options.")
            else:
                for (k, v) in platform:
                    _print_kv_pair(k, v)

            self._debugger.msg_q(MsgLevel.INFO, "")
            self._debugger.msg_q(MsgLevel.INFO, "CPU architecture configuration:")
            self._debugger.msg_q(MsgLevel.INFO, "-------------------------------")
            arch = self._debugger.get_full_arch_config()
            if len(arch) == 0:
                self._debugger.msg_q(
                    MsgLevel.WARN,
                    "No architecture set; configure 'set arduino.platform ...' or "
                    "'set arduino.arch ...' directly.")
                self._debugger.msg_q(
                    MsgLevel.WARN, "See 'list architectures' for available options.")
            else:
                for (k, v) in arch:
                    _print_kv_pair(k, v)

        elif len(argv) == 1 and len(argv[0].split("=", 1)) == 1:
            ### Got something of the form `set x`; just print value of x. ###
            try:
                k = argv[0]
                v = self._debugger.get_conf(k)
                self._debugger.msg_q(MsgLevel.INFO, "%s = %s" % (k, v))
            except KeyError as e:
                self._debugger.msg_q(MsgLevel.ERR, e.args[0])
        else:
            ### Received key and value (`set k v` or `set k=v`); update the config ###
            if len(argv) == 1 and len(argv[0].split("=", 1)) == 2:
                # Support `set k=v` format
                k = argv[0].split("=", 1)[0]
                v = argv[0].split("=", 1)[1]
            else:
                k = argv[0]
                start = 1
                if argv[start] == "=":  # allow 'set x y' or 'set x = y' format.
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
                    v != "0xNone" and v == f'0x{_softint(v[2:], base=16):x}':
                v = int(v[2:], base=16)
            elif isinstance(v, str) and len(v) == 0:
                v = None

            # Actually push this (k, v) pair to the debugger's config state.
            try:
                self._debugger.set_conf(k, v)
            except KeyError as e:
                self._debugger.msg_q(MsgLevel.ERR, e.args[0])


    @Command(keywords=['stack'])
    def _stack_display(self, argv):
        """
        Display memory from a range of addresses on the stack

            Syntax: stack [<count>] [<offset>]

        * count is in words; default is 16 words.
        * data printing starts at ($SP + offset). Offset is given in bytes.
        * If offset is omitted or -1, then "auto-skip" stack frames added by the debugger.
        """
        push_word_len = self._debugger.get_arch_conf('push_word_len')
        stack_model = self._debugger.get_arch_conf('stack_model')
        stack_descending = stack_model == 'full_desc' or stack_model == 'empty_desc'
        stack_full = stack_model == 'full_desc' or stack_model == 'full_asc'

        offset = -1  # auto
        count = 16
        if len(argv) == 1:
            count = int(argv[0])
        elif len(argv) > 1:
            count = int(argv[0])
            offset = int(argv[1])

        (sp, top, snapshot) = self._debugger.get_stack_snapshot(count, offset)
        count = len(snapshot)

        if stack_descending:
            snapshot.reverse()
            dir_coefft = -1  # 'direction coefficient' for modifying printed memory addr.
        else:
            dir_coefft = 1

        highaddr = top + (count * push_word_len)
        if stack_full:
            # Full-descending stack will include $SP but not the 'highaddr'
            highaddr -= push_word_len

        offset = top - sp  # TODO(aaron): this used to have a "- 1" .. check still accurate for AVR?
                           # (if inaccurate, subtract one on 'not stack_full' condition.)
        addr = highaddr

        ramend = self._debugger.get_arch_conf("RAMEND")
        is_at_ramend = addr == ramend
        self._debugger.msg_q(MsgLevel.INFO, f"$SP: {sp:#04x}  Top: {top:#04x}   skip: {offset}")
        print_width = 2 * push_word_len
        for word in snapshot:
            self._debugger.msg_q(MsgLevel.INFO, f'{addr:04x}: {word:0{print_width}x}')
            addr += push_word_len * dir_coefft

        if not is_at_ramend:
            self._debugger.msg_q(MsgLevel.INFO, f'Next: stack 16 {count*push_word_len + offset}')


    @Command(keywords=['stackaddr', 'xs'], completions=[Completions.WORD_SIZE])
    def _stack_mem_read(self, argv):
        """
        Read an address relative to the $SP register

            Syntax: stackaddr [size] <offset (hex)>
        """
        if len(argv) == 0:
            self._debugger.msg_q(MsgLevel.INFO, "Syntax: stackaddr [<size>] <offset (hex)>")
            return
        elif len(argv) == 1:
            size = self._debugger.get_arch_conf("push_word_len")
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
            self._debugger.msg_q(MsgLevel.INFO, f"{v:02x}")
        elif size == 2:
            self._debugger.msg_q(MsgLevel.INFO, f"{v:04x}")
        elif size == 4:
            self._debugger.msg_q(MsgLevel.INFO, f"{v:08x}")


    def __get_frame(self, frame_num):
        """
        Return the stack.CallFrame object for the specified frame of the backtrace.
        """
        frames = self._debugger.get_backtrace(limit=(frame_num + 1))
        if len(frames) <= frame_num:
            return None

        return frames[frame_num]

    @Command(keywords=['frame', '\\f'])
    def _frame(self, argv):
        """
        Display memory contents of a stack frame

            Syntax: frame <n>

        This function displays memory from the n'th stack frame. See the 'backtrace' command
        to get a list of available stack frames.
        """
        if len(argv) == 0:
            self._debugger.msg_q(MsgLevel.INFO, "Syntax: frame <n> -- display memory from n'th stack frame")
            return
        else:
            frame_num = int(argv[0])

        frame = self.__get_frame(frame_num)
        if frame is None:
            self._debugger.msg_q(MsgLevel.ERR, f"Error: No such stack frame #{frame_num}")
            return

        sp = frame.sp
        frame_size = frame.frame_size
        if frame_size is None or frame_size < 0:
            frame_size = 16
            self._debugger.msg_q(
                MsgLevel.WARN,
                f"Warning: could not identify size of stack frame. Defaulting to {frame_size}.")

        self._debugger.msg_q(
            MsgLevel.INFO,
            f'Frame {frame_num} at PC {frame.addr:#04x} in method {frame.demangled}')

        ret_addr = frame.unwound_registers['PC']
        ret_fn_sym = self._debugger.function_sym_by_pc(ret_addr)
        if ret_fn_sym:
            ret_fn = ret_fn_sym.demangled or ret_fn_sym.name
        else:
            ret_fn = '???'
        self._debugger.msg_q(
            MsgLevel.INFO,
            f'Frame {frame_num} size={frame_size}; return address: {ret_addr:#04x} in {ret_fn}')

        push_word_len = self._debugger.get_arch_conf('push_word_len')
        stack_model = self._debugger.get_arch_conf('stack_model')
        stack_descending = stack_model == 'full_desc' or stack_model == 'empty_desc'
        stack_full = stack_model == 'full_desc' or stack_model == 'full_asc'
        if stack_descending:
            dir_coefft = -1  # 'direction coefficient' for modifying printed memory addr.
        else:
            dir_coefft = 1

        if stack_full:
            start_addr = sp + frame_size - push_word_len
            last_addr = sp - push_word_len
        else:
            start_addr = sp + frame_size
            last_addr = sp

        for addr in range(start_addr, last_addr, dir_coefft * push_word_len):
            word = self._debugger.get_sram(addr, push_word_len)
            sp_indicator = ''
            if stack_full and addr == sp:
                sp_indicator = ' <-- $SP'
            self._debugger.msg_q(MsgLevel.INFO,
                                 f'{addr:04x}: 0x{word:0{push_word_len*2}x}{sp_indicator}')

        if not stack_full or frame_size == 0:
            # Print $SP indicator line for empty-descending stack afterward, or print
            # dedicated $SP indicator line for full-descending stack only if this frame
            # uses no stack memory.
            self._debugger.msg_q(MsgLevel.INFO, f'{sp:04x} <-- $SP')

        registers = self._debugger.get_frame_regs(frame_num)
        if registers:
            self._debugger.msg_q(MsgLevel.INFO, '\nRegisters:\n')
            self.__format_registers(registers)



    @Command(keywords=['time'], help_keywords=['tm', 'tu'], completions=[['millis', 'micros']])
    def _print_time(self, argv):
        """
        Read the time from the device in milli- or microseconds

            Syntax: time {millis|micros}

        Prints the time since start (or rollover) as reported by the device.
        """

        if len(argv) == 0:
            self._debugger.msg_q(MsgLevel.INFO, "Syntax: time {millis|micros}")
            return

        if argv[0] == "millis":
            return self._print_time_millis(argv)
        elif argv[0] == "micros":
            return self._print_time_micros(argv)
        else:
            self._debugger.msg_q(MsgLevel.INFO, "Syntax: time {millis|micros}")
            return


    @Command(keywords=['tm'], display_help=False)
    def _print_time_millis(self, argv):
        """
        Print time since device startup (or rollover) in milliseconds.
        """
        self._debugger.msg_q(
            MsgLevel.INFO,
            self._debugger.send_cmd(protocol.DBG_OP_TIME_MILLIS, self._debugger.RESULT_ONELINE))


    @Command(keywords=['tu'], display_help=False)
    def _print_time_micros(self, argv):
        """
        Print time since device startup (or rollover) in microseconds.
        """
        self._debugger.msg_q(
            MsgLevel.INFO,
            self._debugger.send_cmd(protocol.DBG_OP_TIME_MICROS, self._debugger.RESULT_ONELINE))


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
        hwm = 0  # high-water mark for tokens consumed
        if len(argv) == 0:
            self._debugger.msg_q(MsgLevel.INFO, "Syntax: setv <symbol_name> [=] <value> [base=10]")
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
            self._debugger.msg_q(MsgLevel.INFO, "Syntax: setv <symbol_name> [=] <value> [base]")
            return

        if hwm < len(argv):
            try:
                base = int(argv[hwm])
            except ValueError:
                self._debugger.msg_q(
                    MsgLevel.WARN,
                    f"Warning: could not set base={argv[hwm]}. Using base 10")
                base = 10


        sym = self._debugger.lookup_sym(name)
        if sym is None:
            self._debugger.msg_q(MsgLevel.WARN, f"No symbol found: {name}")
            return

        self._last_sym_used = name  # Symbol argument saved as last symbol used.

        # Convert argument to integer. (TODO(aaron): Handle floating point some day?)
        try:
            val = int(val, base=base)
        except ValueError:
            self._debugger.msg_q(MsgLevel.ERR, f"Error: Cannot parse integer value {val} in base {base}")
            return

        # Resolve symbol to memory address
        addr = sym.addr
        size = 1  # set default...
        try:
            size = sym.size  # override if available.
        except KeyError:
            pass

        if size < 1:
            size = 1
        elif size > 4 or size == 3:
            size = 4

        # Resolve logical address to physical address.
        mmap = self.arch_iface.memory_map()
        phys_addr = mmap.logical_to_physical_addr(addr)
        if mmap.access_mechanism_for_addr(addr) == memory_map.ACCESS_TYPE_PGM:
            # We're trying to update something in flash.
            self._debugger.msg_q(
                MsgLevel.ERR,
                f"Error: Cannot write to flash segment at address {addr:x}")
        else:
            # We're trying to update something in SRAM:
            self._debugger.set_sram(phys_addr, val, size)


    @Command(keywords=['sym', "?"], completions=[Completions.SYM])
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
            self._debugger.msg_q(MsgLevel.INFO, "Syntax: sym <substring>")
            return

        # Perform the symbol search and also cache it.
        self._last_sym_search = self._debugger.syms_by_substr(argv[0])
        if len(self._last_sym_search) == 0:
            self._debugger.msg_q(MsgLevel.INFO, "(No matching symbols)")
        elif len(self._last_sym_search) == 1:
            # Found a unique hit.
            self._debugger.msg_q(MsgLevel.INFO, self._last_sym_search[0])
            self._last_sym_used = self._last_sym_search[0]  # last-used symbol is the unique match.
        else:
            # Multiple results
            for i in range(0, len(self._last_sym_search)):
                this_sym = self._last_sym_search[i]
                if this_sym == argv[0]:
                    # Exact match
                    asterisk = "(**)  "
                else:
                    asterisk = ""

                self._debugger.msg_q(MsgLevel.INFO, f"#{i}. {asterisk}{this_sym}")


    @Command(keywords=['syms'])
    def _list_symbols(self, argv):
        """
        List all symbols
        """
        all_syms = self._debugger.syms_by_substr("")
        if len(all_syms) == 0:
            self._debugger.msg_q(MsgLevel.INFO, "No symbol information available")
            return

        for i in range(0, len(all_syms)):
            self._debugger.msg_q(MsgLevel.INFO, f"#{i}. {all_syms[i]}")


    @Command(keywords=['types'])
    def _list_types(self, argv):
        """
        List all defined datatypes
        """

        for (name, typ) in self._debugger.get_debug_info().types():
            self._debugger.msg_q(MsgLevel.INFO, typ)

    @Command(keywords=['addr', '.'], completions=[Completions.SYM])
    def _addr_for_sym(self, argv):
        """
        Show address of a symbol

            Syntax: addr <symbol_name>

        See also: the 'sym' command - search for a precise symbol name via substring.
        After a search with 'sym', you can use #0 (or '$'), #1, #2... to refer to results.
        """
        if len(argv) == 0:
            self._debugger.msg_q(MsgLevel.INFO, "Syntax: addr <symbol_name>")
            return

        sym = self._debugger.lookup_sym(argv[0])
        if sym is None:
            self._debugger.msg_q(MsgLevel.WARN, f"No symbol found: {argv[0]}")
            self._debugger.msg_q(MsgLevel.WARN, f"(Try 'sym {argv[0]}')")
            return

        self._debugger.msg_q(MsgLevel.INFO, f'{sym.demangled}: {sym.addr:08x} ({sym.size})')
        self._last_sym_used = argv[0]  # Looked-up symbol is last symbol used.


    @Command(keywords=['type'], completions=[Completions.SYM_OR_TYPE])
    def _sym_datatype(self, argv):
        """
        Show datatype for symbol or type name

            Syntax: type <name>
        """
        if len(argv) == 0:
            self._debugger.msg_q(MsgLevel.INFO, "Syntax: type <name>")
            return

        registers = self._debugger.get_registers()
        pc = registers["PC"]
        sym = argv[0]
        (kind, typ) = self._debugger.get_debug_info().getNamedDebugInfoEntry(sym, pc)
        if kind is None:
            # Try the global symbol table, especially for a mangled symbol name.
            global_sym = self._debugger.lookup_sym(sym)
            if global_sym is not None and global_sym.type_info is not None:
                self._debugger.msg_q(MsgLevel.INFO, f'{global_sym.type_info}')
            else:
                # Out of options.
                self._debugger.msg_q(MsgLevel.INFO, f'{sym}: <unknown type>')
        elif kind == types.KIND_TYPE or kind == types.KIND_METHOD:
            # Print the type description directly, or print the method signature (which includes
            # the method name) directly
            self._debugger.msg_q(MsgLevel.INFO, f'{typ}')
        else:
            # kind == types.VARIABLE
            self._debugger.msg_q(MsgLevel.INFO, f'{typ.var_name}: {typ.var_type.name}')

        return kind

    @Command(keywords=['die'], completions=[Completions.SYM_OR_TYPE])
    def _print_die(self, argv):
        """
        Show the DIE for a symbol

            Syntax: die [-r[d]] [-ro] [-rt] [frameId] {<symbol_name> | <DIE_offset>}

        Shows a raw debug info entry, with linked or child entries as requested.
        - If a symbol name is given, looks up a global symbol.
        - If a hex value is given, looks up the DIE at the specified offset into .debug_info.
        - If a frame id is specified (from the `backtrace` command) then symbol_name is
          treated as a local. If multiple DW_TAG_variable or DW_TAG_formal_parameter DIEs
          are present in the frame with the same name, all are printed.

        Arguments:
          -r, -rd:  Recurse into child DIEs.
          -ro:      Recurse into DIEs for abstract_origin/specifications.
          -rt:      Recurse into DIEs for symbol's type / base_type(s).
        """
        # TODO(aaron): Also allow 'locals' in completions, and what we search thru, if we have a
        # frame number..
        recurse_die_children = False
        recurse_origin = False
        recurse_types = False

        while len(argv) and argv[0].startswith('-'):
            if argv[0] == '-rd' or argv[0] == '-r':
                recurse_die_children = True
                del argv[0]
            elif argv[0] == '-ro':
                recurse_origin = True
                del argv[0]
            elif argv[0] == '-rt':
                recurse_types = True
                del argv[0]

        if not len(argv):
            # Whether or not we parsed some flags, we don't have a symbol name
            # to work with.
            self._debugger.msg_q(
                MsgLevel.INFO,
                "Syntax: die [-r[d]] [-ro] [-rt] [frameId] {<symbol_name> | <DIE_offset>}")
            return

        sym_name = argv[0]
        sym_addr = None
        frame_id = None

        if sym_name.startswith('0x'):
            try:
                sym_addr = int(sym_name[2:], base=16)
            except ValueError:
                self._debugger.msg_q(MsgLevel.WARN, f"Cannot parse integer value: {sym_name}")
                return
        elif len(sym_name) and sym_name[0] >= '0' and sym_name[0] <= '9' and len(argv) > 1:
            # May be a number indicating a frame id.
            try:
                frame_id = int(sym_name)
                sym_name = argv[1]
            except ValueError:
                # It's not a frame id.
                pass

        if frame_id is not None:
            # Get local variable(s) with the specified name.
            frameScopes = self._debugger.get_frame_vars(frame_id)
            if frameScopes is None:
                self._debugger.msg_q(MsgLevel.WARN, f'No such stack frame {frame_id}')
                return

            nested_methods = self.__get_scoped_locals(frameScopes)

            # Walk through nested methods and filter down to locals / args with the specified name.
            cur = nested_methods
            last_found_scope = None     # How far thru the nested scopes should we print method sigs
                                        # and look for a formal/local with the target name?

            def target_name_filter(arglist):
                return arglist[0].name == sym_name

            i = 0
            while cur is not None:
                cur['formals'] = list(filter(target_name_filter, cur['formals']))
                cur['locals'] = list(filter(target_name_filter, cur['locals']))

                if len(cur['formals']) or len(cur['locals']):
                    # This frame does contain locals or formals w/ the specified name.
                    last_found_scope = i

                cur = cur['next']
                i += 1

            if last_found_scope is None:
                self._debugger.msg_q(MsgLevel.WARN, f'No such local variable: {sym_name}')
                return

            # At least one nested method scope contains a symbol with the specified name.
            cur = nested_methods
            printed_formals = False
            printed_locals = False
            i = 0
            while cur is not None and i <= last_found_scope:
                if printed_formals or printed_locals:
                    self._debugger.msg_q(MsgLevel.INFO, '')

                scope = cur['scope']  # Relevant MethodInfo
                printed_formals = False
                printed_locals = False
                if not scope.is_decl and not scope.is_def:
                    inl_str = 'Inlined method'
                else:
                    inl_str = 'Method'
                self._debugger.msg_q(
                    term.COLOR_GRAY,
                    f'{inl_str} scope: {scope.make_signature(include_class=True)}')
                method_die = scope.get_die()
                if method_die is not None:
                    self._debugger.msg_q(
                        term.COLOR_GRAY,
                        f'Method DIE at offset 0x{method_die.offset:x}')

                formals = cur['formals']
                if len(formals) > 0:
                    printed_formals = True
                    self._debugger.msg_q(MsgLevel.INFO, f"  Formals:")
                    for formal_lst in formals:
                        # formal_lst contains a list of FormalArg entries w/ the same name.
                        for formal in formal_lst:
                            self._debugger.msg_q(
                                MsgLevel.INFO,
                                formal.die_to_str(recurse_die_children, recurse_origin,
                                                  recurse_types))

                locals_list = cur['locals']
                if len(locals_list) > 0:
                    printed_locals = True
                    if printed_formals:
                        self._debugger.msg_q(MsgLevel.INFO, '')

                    self._debugger.msg_q(MsgLevel.INFO, f"  Locals:")
                    for local_var_lst in locals_list:
                        for local in local_var_lst:
                            self._debugger.msg_q(
                                MsgLevel.INFO,
                                local.die_to_str(recurse_die_children, recurse_origin,
                                                 recurse_types))

                cur = cur['next']  # advance linked list ptr.
                i += 1
        else:
            # Look up a global symbol and print its DIE.
            if sym_addr is not None:
                typ = self._debugger.get_debug_info().getDebugInfoEntryByOffset(sym_addr)
            else:
                # Use symbol-name-based lookup.
                registers = self._debugger.get_registers()
                pc = registers["PC"]
                (_, typ) = self._debugger.get_debug_info().getNamedDebugInfoEntry(sym_name, pc)

                if typ is None:
                    # Try .symtab-based lookup.
                    global_sym = self._debugger.lookup_sym(sym_name)
                    if global_sym is not None and global_sym.type_info is not None:
                        typ = global_sym.type_info

            if typ is None:
                self._debugger.msg_q(MsgLevel.INFO, f'{sym_name}: <unknown>')
                return

            self._debugger.msg_q(
                MsgLevel.INFO,
                typ.die_to_str(recurse_die_children, recurse_origin, recurse_types))


    @Command(keywords=['info', '\\i'], completions=[Completions.SYM])
    def _sym_info(self, argv):
        """
        Show info about a symbol: type, addr, value

            Syntax: info <symbol_name>

        This is equivalent to running the 'type', 'addr', and 'print' commands with the same
        symbol name as the argument to each.
        """
        if len(argv) == 0:
            self._debugger.msg_q(MsgLevel.INFO, "Syntax: info <symbol_name>")
            return

        kind = self._sym_datatype(argv)
        if kind != types.KIND_TYPE:
            # For methods and variables, show the address
            self._addr_for_sym(argv)
        if kind == types.KIND_VARIABLE:
            # For variables, show the memory value at that address
            self._print(argv)

    @Command(keywords=['dump'], completions=[Completions.PATH])
    def dump_image(self, argv):
        """
        Save running image state info to file

            Syntax: dump <filename>

        Dumps the state of the connected device to a file for offline debugging.

        Later, you can load the associated dump file with `load <filename>` or start a
        later debugging session with it directly via `arduino-dbg --dump <filename`.
        """
        if len(argv) == 0:
            self._debugger.msg_q(MsgLevel.ERR, "Error: Missing filename")
            self._debugger.msg_q(MsgLevel.INFO, "Syntax: dump <filename>")
            return

        filename = argv[0]
        self._debugger.msg_q(MsgLevel.INFO, f"Writing device state to file ({filename})...")
        dump.capture_dump(self._debugger, filename)
        self._debugger.msg_q(MsgLevel.INFO, "Done.")


    @Command(keywords=['load'], completions=[Completions.PATH])
    def load_dump_image(self, argv):
        """
        Loads state of a connected device from a file for offline debugging

            Syntax: load <filename>

        You can load files saved with the `dump <filename>` command. This will disconnect
        any currently-connected debugging session.
        """
        if len(argv) == 0:
            self._debugger.msg_q(MsgLevel.ERR, "Error: Missing filename")
            self._debugger.msg_q(MsgLevel.INFO, "Syntax: dump <filename>")
            return

        filename = argv[0]
        self._debugger.msg_q(MsgLevel.INFO, f"Loading memory image from {filename}...")
        (debugger, hosted_dbg_serv) = dump.load_dump(
            filename, self._console_printer.print_q,
            history_change_hook=self._history_change_callback)

        # If we were already hosting a debug service for a dump file, remove it and
        # switch to the new one.
        if self._hosted_dbg_service:
            self._hosted_dbg_service.shutdown()
        self._hosted_dbg_service = hosted_dbg_serv

        # Swap out the active debugger instance for one attached to the specified file.
        self._debugger.close()
        self._debugger.release_cmd_lock()   # We hold the cmd lock coming into this method.
                                            # Release it as we close the debugger.
        self._debugger = debugger   # Starts locked. The release() in loop_input_body() will
                                    # release this lock.

    @Command(keywords=['version'])
    def print_version(self, argv):
        """
        Print debugger version

            Syntax: version
        """
        self._debugger.msg_q(MsgLevel.INFO, arduino_dbg.version.FULL_DBG_VERSION_STR)

    @Command(keywords=['license'])
    def print_license(self, argv):
        """
        Print debugger license terms

            Syntax: license
        """
        self._debugger.msg_q(MsgLevel.INFO, arduino_dbg.version.FULL_DBG_VERSION_STR)
        self._debugger.msg_q(MsgLevel.INFO, arduino_dbg.version.LICENSE)


    @Command(keywords=['help'], completions=[Completions.KW])
    def print_help(self, argv):
        """
        Print usage information

            Syntax: help [cmd]

        If given a specific command name, will print the usage info for that command.
        Otherwise, this help message lists all available commands.
        """
        print_command_help(self._debugger, argv)  # call method imported from repl_command module.


    @Command(keywords=['quit', '\\q'])
    def _quit(self, argv):
        """
        Quit the debugger console
        """
        # This method does not actually quit -- that is behavior hardcoded into the REPL.
        # However, having this method in the _cmd_map enables its docstring to be used for
        # `help quit`.
        pass

    def reconnect(self):
        return self._debugger.reconnect()

    def loop_input_body(self):
        """
            Primary function to call inside a loop; executes one flow of Read-eval-print.
            Returns True if we want to quit, False to continue.
        """
        commandMap = Command.getCommandMap()
        compoundCommandMap = CompoundCommand.getCommandMap()

        try:
            self._completer.clear_cache()  # Don't accidentally use suggestions from last input line.
            cmdline = term.readline_input()
        except KeyboardInterrupt:
            # Received '^C'; call the break function
            print('')  # Terminate line after visible '^C' in input.
            self._debugger.get_cmd_lock()
            try:
                self._break()
            except dbg.NoServerConnException:
                pass  # Just go to a clean new line
            finally:
                self._debugger.release_cmd_lock()
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

        self._break_count = 0  # User typed a real non-^C command.

        if len(cmdline) > 0:
            self._append_history()

        try:
            raw_tokens = repl_split(cmdline, incomplete_ok=False)
        except ValueError:
            print("Error: Unclosed quoted string")

        tokens = []
        for t in raw_tokens:  # Filter extra empty-whitespace tokens
            if t == "$":
                if self._last_sym_used:
                    # Replace '$' with last-referenced symbol.
                    tokens.append(self._last_sym_used)
                else:
                    term.write("Warning: no prior symbol reference for '$'", term.WARN)
                    tokens.append("$")  # try it raw...
            elif isinstance(t, str) and t.startswith("#") and len(t) > 1 and t[1:] == str(_softint(t[1:])):
                idx = _softint(t[1:])
                try:
                    # replace '#n' with n'th item in last symbol search.
                    sym = self._last_sym_search[idx]
                    tokens.append(sym)
                except IndexError:
                    term.write(f"Warning: no symbol for index {t}", term.WARN)
                    tokens.append(t)  # try it raw...
            elif t is not None and t != "":
                tokens.append(t)

        if len(tokens) == 0:
            return False

        cmd = tokens[0].strip()
        cmd_obj = None
        cmd_self = self
        pretty_cmd = cmd

        if cmd == "quit" or cmd == "exit" or cmd == "\\q":
            return True  # Actually quit.
        elif cmd in commandMap:
            cmd_obj = commandMap[cmd]
            cmd_args = tokens[1:]
        elif len(tokens) > 1 and CompoundCommand.is_compound_leader(cmd):
            secondary = tokens[1].strip()
            pretty_cmd = cmd + ' ' + secondary
            if (cmd, secondary) in compoundCommandMap:
                cmd_obj = compoundCommandMap[cmd, secondary]
                cmd_args = tokens[2:]

        if not cmd_obj:
            print("Unknown command '%s'; try 'help'." % pretty_cmd)
            return False

        try:
            locked = False
            try:
                # Get ready to send commands...
                while not locked:
                    locked = self._debugger.get_cmd_lock()

                # We have exclusive control of the debugger I/O channels.
                assert locked
                # Proceed to command.
                cmd_obj.invoke(cmd_self, cmd_args)
            finally:
                # Release I/O channel lock.
                if locked:
                    self._debugger.release_cmd_lock()
                # Flush any output gathered during cmd invocation before handling exceptions
                # or proceeding further.
                self._console_printer.join_q()
        except dbg.NoServerConnException as e:
            term.write(f"Error running '{pretty_cmd}': {str(e)}", term.ERR)
        except dbg.DisconnectedException:
            term.write(f"Error: Disconnected from device", term.ERR)
            if not self.reconnect():
                term.write(f"Error: Could not reconnect to device", term.ERR)
        except dbg.InvalidConnStateException as e:
            # Error interrupting the sketch to send command.
            term.write(f"Error running '{pretty_cmd}': {str(e)}", term.ERR)
        except Exception as e:
            if e.__class__ != Exception:
                term.write(f"Got exception of type {e.__class__.__name__}", term.ERR)
            term.write(f"Error running '{pretty_cmd}': {e}", term.ERR)
            if self._debugger.get_conf("dbg.verbose"):
                traceback.print_tb(e.__traceback__)
            else:
                print("For stack trace info, `set dbg.verbose True`")

        return False


    def loop(self):
        """
            The actual main loop.

            Returns the exit status for the program. (0 for success)
        """
        self._console_printer.set_readline_enabled(True)
        quit = False
        last_process_state = None
        while not quit:
            process_state = self._debugger.process_state()
            if process_state != dbg.ProcessState.BREAK and process_state != last_process_state:
                # The program is (maybe?) running. Let the user know how to change that.
                print("Press ^C to interrupt Arduino sketch for debugging.")

            last_process_state = process_state

            # Regardless of process state, we also accept input from the user.
            try:
                quit = self.loop_input_body()
            except KeyboardInterrupt:
                # Received '^C'; call the break function
                print('')  # Terminate line after visible '^C' in input.
                self._debugger.get_cmd_lock()
                try:
                    self._break()  # This will update the process_state to BREAK.
                finally:
                    self._debugger.release_cmd_lock()
            finally:
                self._console_printer.join_q()

        return 0

