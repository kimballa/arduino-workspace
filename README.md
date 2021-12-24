

Arduino Workspace
=====================

A monorepo that contains a number of applications, libraries, and tools I've built.

Apps
----

* `poetrybot`: An arduino art project that displays poetry on a 4x40 char LCD, over I2C.

Libraries
---------

* `i2cparallel`: An 8-bit parallel bus (PCF8574 / PCF8574A / PCA8574) you can interface over I2C.
* `LCD-NHD0440`: Driver for the Newhaven Devices `0440` series of 4x40 char LCDs. Includes a 
  "TTY scrolling" feature that scrolls lines upward as you emit more lines with `print()` /
  `println()`.

Tools
------

* `arduino.mk`: A Makefile that builds and deploys Arduino apps and libraries.
* `dbg`: A debug library including useful logging functions and a client--server interactive 
  debugging console. See `dbg.h` for usage instructions.


Using the arduino.mk Makefile
==============================

Setup and dependencies:
-----------------------

* Install the Arduino IDE and use it to download any Arduino core and board definitions you need, as
  well as associated AVR or ARM compilation toolchains.
* Install the `arduino-cli` tool (https://github.com/arduino/arduino-cli) on your `PATH`.
* Copy `arduino_mk_conf.template` to a file named `~/.arduino_mk.conf` to hold your hardware
  configuration. This is included in the Makefile and follows Makefile syntax. 

Config file:
------------
You should set the following variables:

* `BOARD` - the fqbn of the board you are using (e.g. `arduino:avr:leonardo`)
* `UPLOAD_PORT` - the USB port where you upload to the board. (e.g. `/dev/ttyACM0`)
* `UPLOAD_PROTOCOL` - The protocol to use (e.g. `serial` or `usb`). (Default: `serial`)
* `AVR_PROGRAMMER` - Flash programmer protocol for `avrdude` (Default: `avr109`)
* `install_dir` - the directory tree where `make install` will install static libraries and headers.

These can be overridden on the `make` command line or in any app-specific `Makefile`, but
especially in the case of libraries you probably do not want to tie them to a specific
board hardware configuration.

Usage:
------

* Create a `Makefile` based on `Makefile.template`.
* Set the `prog_name` or `lib_name` field, and declare any `libs` you need.
* Remember that if you depend on a library `foo` that itself depends on `bar`, you must
  list `foo` *before* `bar` in your `libs` list, or else the link-time optimization will
  be unable to find `foo`'s prerequisite symbols in `bar`.
* If your source is not all in the current dir, enuerate the `src_dirs` as needed.
* Run `make` to build your app or library.
* Libraries can be installed to a local lib dir for linking to apps later with `make install`
* Apps can be flashed to the Arduino with `make upload` or `make verify`.
* Use `make config` to see and debug your environment config. Use `make help` to see a list of 
  available targets.

