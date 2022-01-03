# (c) Copyright 2021 Aaron Kimball

import signal
import arduino_dbg.debugger as dbg
import arduino_dbg.protocol as protocol

def _softint(intstr, base=10):
    """
        Try to convert intstr to an int; if it fails, return None instead of ValueError like int()
    """
    try:
        return int(intstr, base)
    except ValueError:
        return None


"""
    The interactive command-line the user interacts with directly.
"""
class Repl(object):

    def __init__(self, debugger):
        self._debugger = debugger
        self._setup_cmd_map()

        signal.signal(signal.SIGINT, signal.default_int_handler)

        self._last_sym_search = []   # results of most-recent symbol substr search.
        self._last_sym_used = None   # last symbol referenced by the user.

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
        m["\\f"] = self._flash

        m["gpio"] = self._gpio

        m["help"] = self.print_help

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

        m["stack"] = self._stack_mem
        m["xs"] = self._stack_mem

        m["time"] = self._print_time
        m["tm"] = self._print_time_millis
        m["tu"] = self._print_time_micros

        m["setv"] = self._set_var
        m["!"] = self._set_var

        m["sym"] = self._symbol_search
        m["?"] = self._symbol_search
        m["syms"] = self._list_symbols

        self._cmd_map = m

    def _backtrace(self, argv):
        print("Unimplemented")


    def _break(self, argv=None):
        self._debugger.send_break()


    def _continue(self, argv=None):
        self._debugger.send_continue()


    def _flash(self, argv):
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
        print("Unimplemented")

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
        """
        if len(argv) == 0:
            print("Syntax: print <symbol_name>")
            return

        sym = self._debugger.lookup_sym(argv[0])
        if sym is None:
            print(f"No symbol found: {argv[0]}")
            return

        self._last_sym_used = argv[0] # Symbol argument saved as last symbol used.

        addr = sym["addr"]
        size = 1 # set default...
        try:
            size = sym["size"] # override if available.
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
            Print register values for user
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
        self._debugger.reset_sketch()


    def _set_conf(self, argv):
        """
            Set or print configuration variables.

            If called with no argv, this dumps the entire config to stdout.
            If called with just a setting name, it prints the setting value.
            If called with "keyname val", "keyname = val", or "keyname=val" then it updates
            the configuration with that value.

            Successful updates to the config are performed silently.
            Attempting to set a config key that does not exist will print a message.

            Successful updates to the config cause the config to be persisted to a conf
            file in the user's home dir by the Debugger object.
        """

        if len(argv) == 0:
            ### No key argument -- display entire configuration ###
            print("Configurable debugger settings:")
            print("-------------------------------")
            for (k, v) in self._debugger.get_full_config():
                if k == k.upper() and isinstance(v, int):
                    print("%s = 0x%x" % (k, v)) # CAPS keys are printed in hex.
                else:
                    print("%s = %s" % (k, v))

            print("")
            print("Arduino platform configuration:")
            print("-------------------------------")
            platform = self._debugger.get_full_platform_config()
            if len(platform) == 0:
                print("No platform set; configure with 'set arduino.platform ...'.")
            else:
                for (k, v) in platform:
                    if k == k.upper() and isinstance(v, int):
                        print("%s = 0x%x" % (k, v)) # CAPS keys are printed in hex.
                    else:
                        print("%s = %s" % (k, v))

            print("")
            print("CPU architecture configuration:")
            print("-------------------------------")
            arch = self._debugger.get_full_arch_config()
            if len(platform) == 0:
                print("No architecture set; configure 'set arduino.platform ...' or " +
                    "'set arduino.arch ...' directly.")
            else:
                for (k, v) in arch:
                    if k == k.upper() and isinstance(v, int):
                        print("%s = 0x%x" % (k, v)) # CAPS keys are printed in hex.
                    else:
                        print("%s = %s" % (k, v))


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


    def _stack_mem(self, argv):
        print("Unimplemented")


    def _print_time(self, argv):
        if len(argv) == 0:
            print("Syntax: time [millis|micros]")
            return

        if argv[0] == "millis":
            return self._print_time_millis(argv)
        elif argv[0] == "micros":
            return self._print_time_micros(argv)
        else:
            print("Syntax: time [millis|micros]")
            return



    def _print_time_millis(self, argv):
        print(self._debugger.send_cmd(protocol.DBG_OP_TIME_MILLIS, self._debugger.RESULT_ONELINE))


    def _print_time_micros(self, argv):
        print(self._debugger.send_cmd(protocol.DBG_OP_TIME_MICROS, self._debugger.RESULT_ONELINE))


    def _set_var(self, argv):
        """
            Update data in RAM, by symbol.
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
        addr = sym["addr"]
        size = 1 # set default...
        try:
            size = sym["size"] # override if available.
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
        if len(argv) == 0:
            print("Syntax: sym <substring>")
            return

        # Perform the symbol search and also cache it.
        self._last_sym_search = self._debugger.syms_by_substr(argv[0])
        if len(self._last_sym_search) == 0:
            print("(No matching symbols)")
        elif len(self._last_sym_search) == 1:
            # Found a unique hit.
            print(self._last_sym_search[i])
            self._last_sym_used = self._last_sym_search[0] # last-used symbol is the unique match.
        else:
            # Multiple results
            for i in range(0, len(self._last_sym_search)):
                print(f"#{i}. {self._last_sym_search[i]}")


    def _list_symbols(self, argv):
        all_syms = self._debugger.syms_by_substr("")
        if len(all_syms) == 0:
            print("No symbol information available")
            return

        for i in range(0, len(all_syms)):
            print(f"#{i}. {all_syms[i]}")


    def _addr_for_sym(self, argv):
        if len(argv) == 0:
            print("Syntax: addr <symbol_name>")
            return

        sym = self._debugger.lookup_sym(argv[0])
        if sym is None:
            print(f"No symbol found: {argv[0]}")
            return

        print(f'{sym["demangled"]}: {sym["addr"]:08x} ({sym["size"]})')
        self._last_sym_used = argv[0] # Looked-up symbol is last symbol used.



    def print_help(self, argv):

        print("Commands")
        print("--------")
        print("addr (.) -- Show address of a symbol")
        print("backtrace (\\t) -- Show the function call stack")
        print("break (^C) -- Interrupt program execution for debugging")
        print("continue (c, \\c) -- Continue main program execution")
        print("flash (xf, \\f) -- Read a flash address on the Arduino")
        print("gpio -- Read or write a GPIO pin")
        print("help -- Show this help text")
        print("mem (x, \\m) -- Read a memory address on the Arduino")
        print("memstats -- Display info about memory map and RAM usage")
        print("poke -- Write to a variable or memory address on the Arduino")
        print("print (v, \\v) -- Print a variable's value")
        print("regs -- Dump contents of registers")
        print("reset -- Reset the Arduino device")
        print("set -- Set or retrieve a config variable of the debugger")
        print("stack (xs) -- Read an address relative to the SP register")
        print("time (tm, tu) -- Read the time from the device in milli- or microseconds")
        print("setv (!) -- Update the value of a global variable")
        print("sym (?) -- Look up symbols containing a substring")
        print("syms -- List all symbols")
        print("quit -- Quit the debugger console")
        print("")
        print("After doing a symbol search with sym or '?', you can reference results by")
        print("number, e.g.: `print #3`  // look up value of 3rd symbol in the list")
        print("The most recently-used such number--or '#0' if '?' gave a unique result--can")
        print("then be referenced as '$'. e.g.: `print $`  // look up the same value again")


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
            return False
        except EOFError:
            # Received '^D'; time to quit
            print('')
            return True

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

        if cmd == "quit" or cmd == "exit":
            return True # Actually quit.
        elif cmd in self._cmd_map.keys():
            fn = self._cmd_map[cmd]
            fn(tokens[1:])
        else:
            print("Unknown command '%s'; try 'help'." % cmd)

        return False


    def loop(self):
        """
            The actual main loop.

            Returns the exit status for the program. (0 for success)
        """
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


