Arduino debugger
================

This is a console debugger for use with sketches running on an embedded Arduino system.
After uploading your sketch to the Arduino, you can connect the serial port to your
computer and debug your running sketch with this application.

You must include a small debugging library (`dbg.cpp` and `dbg.h`) available at
https://github.com/kimballa/arduino-workspace in your application. You should
`#include <dbg.h>` and then follow the instructions in `dbg.h` to enable debugging your
sketch. You will also find instructions in `dbg.h` on the API for creating unconditional
and assertion-based breakpoints, and emitting debug and trace messages.

Setup
-----

* Install the debugger and its dependencies with: `cd debugger/arduino_dbg/ && pip install .`
* If not already installed, install `binutils` through your OS package manager.
* Build the Arduino library with `cd debugger/dbglib && make install`
* Follow instructions in `dbg.h` to include in your application.
* Run `arduino-dbg` to launch the debug console. Use `-h` to see CLI options.
* Set your Arduino platform: e.g.: `set arduino.platform = uno`
* Use the `help` command at the prompt to see available capabilities.

Usage
-----

Typical usage is something like:

```
arduino-dbg -f /path/to/sketch.elf -p /dev/ttyACM0
```

(Assuming your Arduino's USB serial port connection is on `ttyACM0`.)

If you run the `break` command or press `^C` within the debugger, it will pause the
running sketch so you can interrogate or set the values of variables (`print someglobal`),
see a `backtrace`, etc. Programmatic breakpoints can be selectively toggled on and off
with `breakpoint enable` and `breakpoint disable`. On AVR-based Arduinos, you cannot set
new breakpoints from the debugger at runtime.

Within the debugger, you can save a dump of the system registers and memory with `dump
<filename>`. With this dump file and the compiled ELF file of your sketch, you can then
perform offline debugging later with `arduino-dbg -d /path/to/filename.dump`, or by
running `load /path/to/filename.dump` within the debugger.

The dump file will retain the filename of your sketch's ELF file. If you move it to a
different location, you can open the ELF file with `open /path/to/my.elf` within the
debugger after running the `load` command.

There are several additional commands. Typing `help` will list available commands in the
debugger. Type `help <command>` to see usage information for each specific command.

Type `quit`, `exit`, or `\q` to quit the debugger.

Arduino platforms
-----------------

You must specify what Arduino platform you are using with the `set` command. e.g.:

```
set arduino.platform = uno
```

The available platforms are:

* `uno`
* `leonardo`

Please open an issue if you are interested in support for additional platforms. At the
time of this writing, the debugger only supports AVR-based architectures, although ARM
support is planned as future work.

Type `set` to see more configuration variables you can modify. Once set, configuration is
saved to `~/.arduino_dbg.conf` and reused in future sessions. You can delete this file and
restart the debugger to reinitialize the default configuration.

