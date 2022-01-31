
Linting is performed with the `flake8` command. It is configured in the 
eponymous section of the `setup.cfg` file.

This tool is wrapped in a script called `lint-arduino-dbg`. 

e.g. from the `debugger/arduino_dbg` directory, run:

```
bin/lint-arduino-dbg | less
```

(You can run `flake8` directly; this is just to make it obvious how to do so.)
