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
        pass


    def _reset(self, argv):
        self._debugger.send_cmd(["R"], self._debugger.RESULT_SILENT)


    def _set_conf(self, argv):
        if len(argv) == 0:
            for (k, v) in self._debugger.get_full_config():
                print("%s = %s" % (k, v))
        elif len(argv) == 1:
            k = argv[0]
            v = self._debugger.get_conf(k)
            print("%s = %s" % (k, v))
        else:
            k = argv[0]
            start = 1
            if argv[start] == "=": # allow 'set x y' or 'set x = y' format.
                start = start + 1
            v = " ".join(argv[start:])
            self._debugger.set_conf(k, v)


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
