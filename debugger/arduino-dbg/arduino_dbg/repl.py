# (c) Copyright 2021 Aaron Kimball

import functools
import inspect
import readline
import signal
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


class Repl(object):
    """
    The interactive command-line the user interacts with directly.
    """

    def __init__(self, debugger):
        self._debugger = debugger
        self._setup_cmd_map()

        signal.signal(signal.SIGINT, signal.default_int_handler)

        self._last_sym_search = []   # results of most-recent symbol substr search.
        self._last_sym_used = None   # last symbol referenced by the user.

        self._break_count = 0 # How many times has the user mashed ^C?

    def _setup_cmd_map(self):
        m = {}
        m["addr"] = self._addr_for_sym
        m["."] = self._addr_for_sym

        m["backtrace"] = self._backtrace
        m["\\t"] = self._backtrace

        m["break"] = self._break
        m["continue"] = self._continue
        m["c"] = self._continue
        m["\\c"] = self._continue

        m["flash"] = self._flash
        m["xf"] = self._flash

        m['frame'] = self._frame
        m["\\f"] = self._frame

        m["gpio"] = self._gpio

        m["help"] = self.print_help

        m["info"] = self._sym_info
        m["\\i"] = self._sym_info

        m["mem"] = self._mem
        m["x"] = self._mem
        m["\\m"] = self._mem

        m["memstats"] = self._memstats

        m["poke"] = self._poke

        m["print"] = self._print
        m["v"] = self._print
        m["\\v"] = self._print

        m["regs"] = self._regs
        m["reset"] = self._reset
        m["set"] = self._set_conf

        m["stack"] = self._stack_display

        m["stackaddr"] = self._stack_mem_read
        m["xs"] = self._stack_mem_read

        m["setv"] = self._set_var
        m["!"] = self._set_var

        m["sym"] = self._symbol_search
        m["?"] = self._symbol_search
        m["syms"] = self._list_symbols

        m["time"] = self._print_time
        m["tm"] = self._print_time_millis
        m["tu"] = self._print_time_micros

        m["type"] = self._sym_datatype
        m["types"] = self._list_types

        m["quit"] = self._quit
        m["exit"] = self._quit
        m["\\q"] = self._quit

        self._cmd_map = m

    def _synonyms(self, cmd):
        """
        Return a list of all synonymous commands that run the same method as 'cmd'.
        """

        cmd_func = self._cmd_map[cmd]
        lst = []
        for (name, func) in self._cmd_map.items():
            if func == cmd_func:
                lst.append(name)

        return lst



    def _backtrace(self, argv):
        """
        Enumerate the method calls on the stack, along with the return point in the source.

            Syntax: backtrace

        This function lists all current stack frames by starting with $PC and $SP and walking
        up the stack to identify frame boundaries and method return points. The top-most call
        on the stack will be #0, followed by #1, #2, etc; 'main()' will be the bottom-most
        method named.

        See also the 'frame' command, which shows the stack memory for a specific stack frame.
        """
        frames = self._debugger.get_backtrace()
        for i in range(0, len(frames)):
            frame = frames[i]

            if frame.source_line:
                src = f'  ({frame.source_line})'
            else:
                src = ''
            print(f"{i}. {frame.addr:04x}: {frame.demangled}{src}")
            if len(frame.demangled_inline_chain) > 1:
                print(f"    Inlined method calls: {' in '.join(frame.demangled_inline_chain)}")


    def _break(self, argv=None):
        """
        Interrupt the running program and enable debugging at the current $PC.
        """
        self._debugger.send_break()


    def _continue(self, argv=None):
        """
        Continue running the program after an interrupt or breakpoint.
        """
        self._debugger.send_continue()


    def _flash(self, argv):
        """
        Access data in the flash memory segment.

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


    def _gpio(self, argv):
        """
        Set or retrieve a gpio pin value.

            Syntax: gpio <pinId> [<value>]
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



    def _memstats(self, argv):
        """
        Print metrics about how much memory is in use.
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


    def _mem(self, argv):
        """
        Retrieve data from RAM, by address.

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


    def _poke(self, argv):
        """
        Overwrite memory in RAM with the specified value.

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


    def _print(self, argv):
        """
        Retrieve data from flash or RAM, by symbol.

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


    def _regs(self, argv):
        """
        Print current values of registers.
        """
        MAX_WIDTH = 65

        registers = self._debugger.get_registers()

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


    def _reset(self, argv=None):
        """
        Reset the device.

        Execution resumes at the program entry point. This will disconnect the debugger.
        """
        self._debugger.reset_sketch()


    def _set_conf(self, argv):
        """
        Set or print configuration variables.

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


    def _stack_display(self, argv):
        """
        Read several values from the stack and display them.

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


    def _stack_mem_read(self, argv):
        """
        Read a memory address relative to SP

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


    def _frame(self, argv):
        """
        Display stack contents of a stack frame.

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

        addr = sp + frame_size # Ensure `addr` initialized in case frame_size == 0.
        for addr in range(sp + frame_size, sp, -1):
            b = self._debugger.get_sram(addr, 1)
            print(f'{addr:04x}: {b:02x}')

        print(f'{addr-1:04x} <-- $SP')


    def _print_time(self, argv):
        """
        Prints the time since start (or rollover) as reported by the device.

            Syntax: time {millis|micros}
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



    def _print_time_millis(self, argv):
        """
        Print time since device startup in milliseconds.
        """
        print(self._debugger.send_cmd(protocol.DBG_OP_TIME_MILLIS, self._debugger.RESULT_ONELINE))


    def _print_time_micros(self, argv):
        """
        Print time since device startup (or rollover) in microseconds.
        """
        print(self._debugger.send_cmd(protocol.DBG_OP_TIME_MICROS, self._debugger.RESULT_ONELINE))


    def _set_var(self, argv):
        """
        Update data in RAM, by symbol.

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


    def _symbol_search(self, argv):
        """
        Search the symbol database for symbols that contain a given substring.

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


    def _list_symbols(self, argv):
        """
        syms - List all symbols.
        """
        all_syms = self._debugger.syms_by_substr("")
        if len(all_syms) == 0:
            print("No symbol information available")
            return

        for i in range(0, len(all_syms)):
            print(f"#{i}. {all_syms[i]}")

    def _list_types(self, argv):
        """
        types - List all types.
        """

        for (name, typ) in types.types():
            print(typ)

    def _addr_for_sym(self, argv):
        """
        Resolve a symbol to a memory address.

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

    def _sym_datatype(self, argv):
        """
        Show datatype for symbol or type name.

            Syntax: type <name>
        """
        if len(argv) == 0:
            print("Syntax: type <name>")
            return

        registers = self._debugger.get_registers()
        pc = registers["PC"]
        sym = argv[0]
        (kind, typ) = types.getTypeByName(sym, pc)
        if kind is None:
            print(f'{sym}: <unknown type>')
        elif kind == types.TYPE or kind == types.METHOD:
            # Print the type description directly, or print the method signature (which includes
            # the method name) directly
            print(f'{typ}')
        else:
            # kind == types.VARIABLE
            print(f'{sym}: {typ.name}')

        return kind

    def _sym_info(self, argv):
        """
        Show info about a symbol: type, addr, value.

            Syntax: info <symbol_name>

        This is equivalent to running the 'type', 'addr', and 'print' commands with the same
        symbol name as the argument to each.
        """
        if len(argv) == 0:
            print("Syntax: info <symbol_name>")
            return

        kind = self._sym_datatype(argv)
        if kind != types.TYPE:
            # For methods and variables, show the address
            self._addr_for_sym(argv)
        if kind == types.VARIABLE:
            # For variables, show the memory value at that address
            self._print(argv)


    def print_help(self, argv):
        """
        Print usage information.

        Syntax: help [cmd]

        If given a specific command name, will print the usage info for that command.
        Otherwise, this help message lists all available commands.
        """

        if len(argv) > 0:
            try:
                cmd = argv[0]
                cmd_method = self._cmd_map[cmd]
                synonyms = self._synonyms(cmd)
                if len(synonyms) > 1:
                    print(f"  '{cmd}' ({', '.join(synonyms)})\n")
                else:
                    print(f"  '{cmd}'\n")
                print(inspect.cleandoc(cmd_method.__doc__))
            except:
                print(f"Error: No command {argv[0]} found.")
                print("Try 'help' to list all available commands.")
                print("Use 'quit' to exit the debugger.")

            return

        print("Commands")
        print("--------")
        print("addr (.) -- Show address of a symbol")
        print("backtrace (\\t) -- Show the function call stack")
        print("break (^C) -- Interrupt program execution for debugging")
        print("continue (c, \\c) -- Continue main program execution")
        print("flash (xf) -- Read a flash address on the Arduino")
        print("frame (\\f) -- Show memory contents of a stack frame")
        print("gpio -- Read or write a GPIO pin")
        print("help -- Show this help text")
        print("info (\\i) -- Show info about a symbol: type, addr, value")
        print("mem (x, \\m) -- Read a memory address on the Arduino")
        print("memstats -- Display info about memory map and RAM usage")
        print("poke -- Write to a variable or memory address on the Arduino")
        print("print (v, \\v) -- Print a variable's value")
        print("regs -- Dump contents of registers")
        print("reset -- Reset the Arduino device")
        print("set -- Set or retrieve a config variable of the debugger")
        print("stack -- Display memory from a range of addresses on the stack")
        print("stackaddr (xs) -- Read an address relative to the SP register")
        print("setv (!) -- Update the value of a global variable")
        print("sym (?) -- Look up symbols containing a substring")
        print("syms -- List all symbols")
        print("time (tm, tu) -- Read the time from the device in milli- or microseconds")
        print("type -- Show datatype for symbol")
        print("types -- List all defined datatypes")
        print("quit (\q) -- Quit the debugger console")
        print("")
        print("After doing a symbol search with sym or '?', you can reference results by")
        print("number, e.g.: `print #3`  // look up value of 3rd symbol in the list")
        print("The most recently-used such number--or '#0' if '?' gave a unique result--can")
        print("then be referenced as '$'. e.g.: `print $`  // look up the same value again")
        print("")
        print("For more information, type: help <command>")


    def _quit(self, argv):
        """
        Exit the debugger.
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
        elif cmd in self._cmd_map.keys():
            try:
                fn = self._cmd_map[cmd]
                fn(tokens[1:])
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


