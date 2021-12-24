
Arduino debugger system
========================

Goals, from easiest to hardest:
* Provide useful output over usb/serial connection for diagnostics (tracing, var logging, etc).
* Provide useful hardcoded on-host debug capabilities: `BREAK()`, `ASSERT()`, `TRACE()`,
  `DBGPRINT()`, etc.
  * Use macros for hardcoded capabilities, so they optimize away to nothing if debugging disabled.
* Enable a client program on the dev machine to interrogate the host.
  * `BREAK()` calls into "server" that responds to requests from client (val @ mem addr, regs,
    stack frames, etc)
  * client can send an 'interrupt' over usb that invokes the server. (register a Timer interrupt
    that looks for `Serial.available() > 0` every second or so. then invoke server from within ISR.
* Support as many Arduino architectures as possible, starting with `avr`/`mega32u4`.
* Client CLI debugger capabilities:
  * read/write specific mem addr (peek/poke).
  * parse ELF file and link back to source code.
  * read/write variables by name [in type-aware fashion].
    * create a watchlist to dump all at once.
    * scope-aware: `locals` vs `globals`, handle aliasing.
  * pretty-print call stack including function calls and arg names/values.
    * print metrics about mem usage: stack size, globals, heap
  * register/remove legitimate hardware breakpoints
  * step through code execution 
  * register 'watch' variables.
  * manipulate gpio ports
  * ... manually set registers 
  * Initiate soft reset (via watchdog)


Configuration
--------------

```
#include<dbg.h>

SETUP() { // replace `void setup()` with this
  /* your setup fn. */
}
```

This unwraps to:
```
#define SETUP() \
  void __user_setup(); /* fwd-declare */ \
  void setup() {              \
    * set up timer irq 
    * wait for `if(Serial)` if WAIT_FOR_CONNECT defined.
    * start in BREAK() if START_PAUSED defined.

    __user_setup(); /* normal setup */ \
  }                          \
  /* user's code below... */ \
  void __user_setup()         \
```

(and if `DEBUG` isn't defined, just `#define SETUP() void setup()`)
... or check `#if !defined(NDEBUG)` instead to play nice with g++?


Use a macro to allow alternate `Serial` interface usage.
(`#define DBG_SERIAL Serial`)


* Just use '\n' as CONTINUE command so you can pop out of BREAK() without special client.
* Maybe use github.com/eliben/pyelftools for ELF parsing?
