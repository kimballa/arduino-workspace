Current stats:
```
     9660 data, 514 RAM
     9714 / 514 (wdt.h, reset)
     9826 / 514 (length byte and STACKREL)
     9880 / 514 (poke)
    12016 / 576 (stacktrace) <<*with instrumentation; 9998/534 without>>
    11750 / 546 (gpio; more selective stacktrace instrumentation; *10114/534)
    11838 / 552 (memory usage reporting; *10192/540)
    11838 / 552 *v1.0*
    12870 / 572 (with dual call stack) <-- Extra size is 18 bytes / fn o.h. of including call_site.
    12708 / 572 optimized instrumentation
    10124 / 520 *v2.0* - removed need for instrumentation to capture stack traces.
```

empty program:  3896 / 150
with dbg-gpio:  5564 / 173 (+1668)
dbg-memusage:   5618 / 179
optimized:      5566 / 159 (real stack walking, no more instrumentation)

Minimum debugger o.h. is 1670 flash, 9 sram bytes.

