
Arduino debugger
================

* Install the debugger and its dependencies with: `cd debugger/arduino_dbg/ && pip install .`
* If not already installed, install `binutils` through your OS package manager.
* Build the Arduino library with `cd debugger/dbglib && make install`
* Follow instructions in `dbg.h` to include in your application.
* Run `arduino-dbg` to launch the debug console. Use `-h` to see CLI options.
* Use the `help` command at the prompt to see available capabilities.

Typical usage is something like:

```
arduino-dbg -f /path/to/sketch.elf -p /dev/ttyACM0
```

(Assuming your Arduino's USB serial port connection is on `ttyACM0`.)

