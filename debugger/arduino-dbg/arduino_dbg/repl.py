# (c) Copyright 2021 Aaron Kimball

import signal
import arduino_dbg.debugger as dbg

"""
    The interactive command-line the user interacts with directly.
"""
class Repl(object):

    def __init__(self, debugger):
        self._debugger = debugger
        self._setup_cmd_map()

        signal.signal(signal.SIGINT, signal.default_int_handler)

    def _setup_cmd_map(self):
        m = {}
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

        self._cmd_map = m

    def _backtrace(self, argv):
        pass


    def _break(self, argv):
        print ("broken")


    def _continue(self, argv):
        pass


    def _flash(self, argv):
        pass


    def _gpio(self, argv):
        pass


    def _mem(self, argv):
        pass


    def _poke(self, argv):
        pass


    def _print(self, argv):
        pass


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


    def _reset(self, argv):
        self._debugger.send_cmd(["R"], self._debugger.RESULT_SILENT)


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
            # No 
            print("Configurable debugger settings:")
            print("-------------------------------")
            for (k, v) in self._debugger.get_full_config():
                print("%s = %s" % (k, v))

            print("")
            print("Arduino platform configuration:")
            print("-------------------------------")
            platform = self._debugger.get_full_platform_config()
            if len(platform) == 0:
                print("No platform set; configure with 'set arduino.platform ...'.")
            else:
                for (k, v) in platform:
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
                    print("%s = %s" % (k, v))

            
        elif len(argv) == 1 and len(argv[0].split("=")) == 1:
            # Got something of the form `set x`; just print value of x.
            try:
                k = argv[0]
                v = self._debugger.get_conf(k)
                print("%s = %s" % (k, v))
            except KeyError as e:
                print(str(e))
        else:
            if len(argv) == 1 and len(argv[0].split("=")) == 2:
                # Support `set k=v` format
                k = argv[0].split("=")[0]
                v = argv[0].split("=")[1]
            else:
                k = argv[0]
                start = 1
                if argv[start] == "=": # allow 'set x y' or 'set x = y' format.
                    start = start + 1
                v = " ".join(argv[start:])

            try:
                self._debugger.set_conf(k, v)
            except KeyError as e:
                print(str(e))


    def _stack_mem(self, argv):
        pass


    def _print_time(self, argv):
        pass


    def _print_time_millis(self, argv):
        pass


    def _print_time_micros(self, argv):
        pass


    def _set_var(self, argv):
        pass


    def _symbol_search(self, argv):
        pass


    def print_help(self, argv):

        print("backtrace (\\t) -- Show the function call stack")
        print("break (^C) -- Interrupt program execution for debugging")
        print("continue (c, \\c) -- Continue main program execution")
        print("flash (xf, \\f) -- Read a flash address on the Arduino")
        print("gpio -- Read or write a GPIO pin")
        print("help -- Show this help text")
        print("mem (x, \\m) -- Read a memory address on the Arduino")
        print("poke -- Write to a variable or memory address on the Arduino")
        print("print (v, \\v) -- Print a variable's value")
        print("regs -- Dump contents of registers")
        print("reset -- Reset the Arduino device")
        print("set -- Set a config variable of the debugger")
        print("stack (xs) -- Read an address relative to the SP register")
        print("time (tm, tu) -- Read the time from the device in milli- or microseconds")
        print("setv (!) -- Update the value of a global variable")
        print("sym (?) -- Look up symbols containing a substring")
        print("quit -- Quit the debugger console")


    def loop(self):
        """
            Primary function to call inside a loop; executes one flow of Read-eval-print.
            Returns True if we want to quit, False to continue.
        """

        try:
            cmdline = input("(adbg) ")
        except KeyboardInterrupt:
            # Received '^C'; call the break function
            print('') # Terminate line after visible '^C' in input.
            self._break([])
            return False

        raw_tokens = cmdline.split(" ")
        tokens = []
        for t in raw_tokens: # Filter extra empty-whitespace tokens
            if t is not None and t != "":
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
