

Arduino Workspace
=====================

A monorepo that contains a number of applications, libraries, and tools I've built.

Apps
----

* `poetrybot`: An arduino art project that displays poetry on a 4x40 char LCD, over I2C.

Libraries
---------

* `i2cparallel`: An 8-bit parallel bus (PCF8574 / PCF8574A) you can interface over I2C.
* `LCD-NHD0440`: Driver for the Newhave Devices 0440 series of 4x40 char LCDs.

Tools
------

* `arduino.mk`: A Makefile that builds and deploys Arduino apps and libraries.


Using the arduino.mk Makefile
==============================

Setup:

* Install the Arduino IDE and use it to download any Arduino core and board definitions you need.
* Install the `arduino-cli` tool (https://github.com/arduino/arduino-cli) on your `PATH`.
* Create a file named `~/.arduino_mk.conf` to hold your hardware configuration. This is included
  in the Makefile and follows Makefile syntax. 

You should set the following variables:

* `BOARD` - the fqbn of the board you are using (e.g. `arduino:avr:leonardo`)
* `UPLOAD_PORT` - the USB port where you upload to the board. (e.g. `/dev/ttyACM0`)
* `UPLOAD_PROTOCOL` - The protocol to use (e.g. `serial` or `usb`). (Default: `serial`)
* `install_dir` - the directory tree where `make install` will install static libraries and headers.

Usage:

* Create a `Makefile` based on `Makefile.template`.
* Set the `prog_name` or `lib_name` field, and declare any `libs` you need.
* If your source is not all in the current dir, enuerate the `src_dirs` as needed.
* Run `make` to build your app or library.
* Libraries can be installed to a local lib dir for linking to apps later with `make install`
* Apps can be flashed to the Arduino with `make upload` or `make verify`.
* Use `make config` to see and debug your environment config. Use `make help` to see a list of 
  available targets.

