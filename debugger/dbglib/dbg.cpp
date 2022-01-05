// (C) Copyright 2021 Aaron Kimball

#include "dbg.h"
#include <Stream.h>

#ifndef FPSTR
#define FPSTR(pstr_pointer) (reinterpret_cast<const __FlashStringHelper *>(pstr_pointer))
#endif /* FPSTR */

#define __dbg_internal_stack_frame_limit (min(DBG_MAX_STACK_FRAMES, __DBG_STACK_FRAME_LIMIT))

// Debugger status bits.
volatile uint8_t debug_status = 0;

#ifdef DBG_ENABLED
static volatile void* pcAtBreakpoint = NULL; // PC where break triggered.
#endif

// Forward declarations.
extern "C" {
  static void __dbg_service() __attribute__((no_instrument_function));
  static void __dbg_callstack() __attribute__((no_instrument_function));
  static inline void __dbg_reset() __attribute__((no_instrument_function));
}

ISR(TIMER1_COMPA_vect) __attribute__((no_instrument_function));

#define DBG_STATUS_IN_BREAK  (0x1)  // True if we are inside the debugger service.


// The debugger client sends sentences beginning with a DBG_OP_ and ending with DBG_END.
// The sentences may usually contain one or more whitespace-delimited base-10 integer arguments.
// Our commands do not use [0-9] so any extra args are consumed harmlessly rather than be
// accidentally interpreted as other commands.
#define DBG_END          '\n' // end of debugger sentence.

#define DBG_OP_RAMADDR   '@' // Return data at RAM address
#define DBG_OP_STACKREL  '$' // Return data at addr relative to SP.
#define DBG_OP_BREAK     'B' // Break execution of the program. (Redundant if within server)
#define DBG_OP_CONTINUE  'C' // continue execution
#define DBG_OP_FLASHADDR 'f' // Return data at Flash address.
#define DBG_OP_POKE      'K' // Insert data to RAM address.
#define DBG_OP_MEMSTATS  'm' // Describe memory usage
#define DBG_OP_PORT_IN   'p' // read gpio pin
#define DBG_OP_PORT_OUT  'P' // write gpio pin
#define DBG_OP_RESET     'R' // Reset CPU.
#define DBG_OP_REGISTERS 'r' // Dump registers
#define DBG_OP_CALLSTACK 's' // Return call stack info
#define DBG_OP_TIME      't' // Return cpu timekeeping info.
#define DBG_OP_NONE      DBG_END

#define DBG_RET_PRINT    ('>') // prefix for logged messages that debugger client
                               // should output verbatim to console.

// Character appended to 't' (OP_TIME) to specify units to report.
// e.g. Use the command "tm\n" to get the current millis().
#define DBG_TIME_MILLIS 'm' // get time in ms
#define DBG_TIME_MICROS 'u' // get time in us

/**
 * Method called pre-init to disable watchdog.
 * The watchdog timer remains running after watchdog-fired reset, which will just
 * cause infinite resetting in normal applications. Clear it.
 */
void __dbg_disable_watchdog() {
  MCUSR = 0;
  wdt_disable();
}

/**
 * Program the watchdog timer to run for a short period, with system reset on watchdog
 * timeout. Then wait 'forever' so the watchdog timer fires, causing a system reset.
 */
static inline void __dbg_reset() {
  wdt_reset();
  wdt_enable(WDTO_15MS);
  while (true) { }; // Wait for watchdog reset to fire.
}

/**
 * Setup function for debugger; called before user's setup function.
 * Activate I/O and IRQs required for debugger operation.
 */
void __dbg_setup() {
  DBG_SERIAL.begin(DBG_SERIAL_SPEED);

  // Set up timer IRQ: 1Hz on Timer1
  // (see https://www.instructables.com/Arduino-Timer-Interrupts/)
  cli();
  TCCR1A = 0; // set entire TCCR1A register to 0
  TCCR1B = 0; // same for TCCR1B
  TCNT1  = 0; // initialize counter value to 0
  // set compare match register for 1Hz increments
  OCR1A = (F_CPU / 1024) - 1; // 15624 = (16*10^6) / (1*1024) - 1 (must be <65536)
  TCCR1B |= (1 << WGM12); // turn on CTC mode
  // Set CS10 and CS12 bits for 1024 prescaler
  TCCR1B |= (1 << CS12) | (1 << CS10);
  // enable timer compare interrupt
  TIMSK1 |= (1 << OCIE1A);
  sei();
}

// Keyword sent from sketch/server to client whenever breakpoint is triggered (either
// from sketch source code or via interrupt) to let client know we're in the dbg server.
static const char _paused_msg[] PROGMEM = "Paused";

/**
 * Called at breakpoint in user code (or via ISR if serial traffic arrives). Starts a service
 * that communicates over DBG_SERIAL about the state of the CPU until released to continue by
 * the client.
 */
static void __dbg_service() {
  debug_status |= DBG_STATUS_IN_BREAK; // Mark the service as started so we don't recursively re-enter.
  // In order to communicate over UART or USB Serial, we need to keep servicing interrupts within
  // debugger, even if called via IRQ.
  sei();
  // TODO(aaron): Give user a way to disable interrupts of theirs via callback SPI before sei?

  static uint8_t cmd;

  DBG_SERIAL.println(FPSTR(_paused_msg));

  while (true) {
    while (!DBG_SERIAL.available()) { };

    cmd = DBG_SERIAL.read();
    if (cmd == DBG_OP_NONE) {
      continue; // Empty input line.
    }

    // Interpret client request sentence.
    unsigned int addr = 0;
    unsigned long value = 0;
    int offset = 0;
    uint8_t b = 0;
    switch(cmd) {
    case DBG_OP_BREAK:
      DBG_SERIAL.println(FPSTR(_paused_msg));
      break;
    case DBG_OP_RESET:
      __dbg_reset();
      break;
    case DBG_OP_CALLSTACK:
      __dbg_callstack();
      break;
    case DBG_OP_RAMADDR:
      b = DBG_SERIAL.parseInt(LookaheadMode::SKIP_WHITESPACE);
      addr = DBG_SERIAL.parseInt(LookaheadMode::SKIP_WHITESPACE);
      if (4 == b) {
        DBG_SERIAL.println(*((uint32_t*)addr), HEX);
      } else if (2 == b) {
        DBG_SERIAL.println(*((uint16_t*)addr), HEX);
      } else { // expect '1' but fallback to 1 byte in any err mode.
        DBG_SERIAL.println(*((uint8_t*)addr), HEX);
      }
      break;
    case DBG_OP_STACKREL:
      b = DBG_SERIAL.parseInt(LookaheadMode::SKIP_WHITESPACE);
      offset = DBG_SERIAL.parseInt(LookaheadMode::SKIP_WHITESPACE);
      if (4 == b) {
        DBG_SERIAL.println(*((uint32_t*)(SP + offset)), HEX);
      } else if (2 == b) {
        DBG_SERIAL.println(*((uint16_t*)(SP + offset)), HEX);
      } else { // expect '1' but fallback to 1 byte in any err mode.
        DBG_SERIAL.println(*((uint8_t*)(SP + offset)), HEX);
      }
      break;
    case DBG_OP_FLASHADDR:
      b = DBG_SERIAL.parseInt(LookaheadMode::SKIP_WHITESPACE);
      addr = DBG_SERIAL.parseInt(LookaheadMode::SKIP_WHITESPACE);
      if (4 == b) {
        DBG_SERIAL.println((uint32_t)pgm_read_dword(addr));
      } else if (2 == b) {
        DBG_SERIAL.println((uint16_t)pgm_read_word(addr));
      } else { // expect '1' but fallback to 1 byte in any err mode.
        DBG_SERIAL.println((uint8_t)pgm_read_byte(addr));
      }
      break;
    case DBG_OP_POKE:
      b = DBG_SERIAL.parseInt(LookaheadMode::SKIP_WHITESPACE);
      addr = DBG_SERIAL.parseInt(LookaheadMode::SKIP_WHITESPACE);
      value = DBG_SERIAL.parseInt(LookaheadMode::SKIP_WHITESPACE);
      if (4 == b) {
        *((uint32_t*)addr) = (uint32_t) value;
      } else if (2 == b) {
        *((uint16_t*)addr) = (uint16_t) value;
      } else { // expect '1' but fallback to 1 byte in any err mode.
        *((uint8_t*)addr) = (uint8_t) value;
      }
      break;
    case DBG_OP_MEMSTATS:
      // Print back stats on memory usage.
      // RAMSTART and RAMEND are hardcoded and can be loaded from a device profile on the
      // client. The other values are dynamic and must be reported live, here. __malloc_heap_end
      // will be 0 if the dynamic allocator isn't initialized; __malloc_heap_start will point
      // to the end of the .bss section, where allocatable memory begins.
#ifndef DBG_NO_MEM_REPORT
      DBG_SERIAL.println(SP, HEX);
      DBG_SERIAL.println((uint16_t)__malloc_heap_end, HEX);
      DBG_SERIAL.println((uint16_t)__malloc_heap_start, HEX);
#endif /* DBG_NO_MEM_REPORT */
      DBG_SERIAL.println('$');
      break;
    case DBG_OP_REGISTERS:
      // 32 general purpose registers exist at 0x00..0x1F (mega32u4 ds fig. 4-2)
      for(addr = 0; addr < 32; addr++) {
        DBG_SERIAL.println(*((uint8_t*)addr), HEX);
      }
      // Special registers: SP (note: 16 bit), SREG
      DBG_SERIAL.println((uint16_t)SP, HEX);
      DBG_SERIAL.println((uint8_t)SREG, HEX);
      DBG_SERIAL.println('$');
      // TODO(aaron): Do we need RAMPX..Z, EIND? See avr/common.h for defs.
      break;
#ifdef DBG_NO_GPIO
    case DBG_OP_PORT_IN:
      DBG_SERIAL.println('0');
      break;
#else /* DBG_NO_GPIO */
    case DBG_OP_PORT_IN:
      addr = DBG_SERIAL.parseInt(LookaheadMode::SKIP_WHITESPACE);
      DBG_SERIAL.println((uint8_t)digitalRead((uint8_t)addr), HEX);
      break;
    case DBG_OP_PORT_OUT:
      // Drive a specified value on a gpio pin. To prevent hardware damage by the
      // debugger, the pin must already be configured as OUTPUT mode.
      addr = DBG_SERIAL.parseInt(LookaheadMode::SKIP_WHITESPACE);
      value = DBG_SERIAL.parseInt(LookaheadMode::SKIP_WHITESPACE);
      digitalWrite((uint8_t)addr, value != 0);
      break;
#endif /* DBG_NO_GPIO */
    case DBG_OP_TIME:
#ifdef DBG_NO_TIME
      DBG_SERIAL.println('0');
#else /* DBG_NO_TIME */
      while (!DBG_SERIAL.available()) { };
      b = DBG_SERIAL.read();
      if (b == DBG_TIME_MILLIS) {
        DBG_SERIAL.println((uint32_t)millis(), DEC);
      } else if (b == DBG_TIME_MICROS) {
        DBG_SERIAL.println((uint32_t)micros(), DEC);
      } else {
        DBG_SERIAL.print(DBG_RET_PRINT);
        DBG_SERIAL.println(F("Error\n0"));
      }
#endif /* DBG_NO_TIME */
      break;
    case DBG_OP_CONTINUE: // Continue main program execution; exit debugger.
      // Eat remainder of the line.
      b = 0;
      while ((char)b != DBG_END) {
        while (!DBG_SERIAL.available()) { }
        b = DBG_SERIAL.read(); // consume expected EOL marker before debugger exit.
      }
      DBG_SERIAL.println(F("Continuing")); // client expects this exact string
      goto exit_loop;
      break;
    default: // Unknown command or unconsumed trailing junk from prior command.
      break;
    }

    if (DBG_SERIAL.available() && DBG_SERIAL.peek() == DBG_END) {
      DBG_SERIAL.read(); // consume expected EOL marker before reading next command.
    }
  }
exit_loop:

  debug_status &= ~DBG_STATUS_IN_BREAK; // Mark debug service as closed.
}

static const char _breakpoint_msg[] PROGMEM = "Breakpoint at ";
static const char _assert_fail_msg[] PROGMEM = "Assertion failure in ";
static const char _separator[] PROGMEM = "): ";

bool __dbg_assert(bool test, const char *assertStr, const char *funcOrFile,
    const unsigned int lineno) {

  if (test) {
    return true; // Assert succeeded.
  }

  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.print(FPSTR(_assert_fail_msg));
  DBG_SERIAL.print(funcOrFile);
  DBG_SERIAL.print('(');
  DBG_SERIAL.print(lineno, DEC);
  DBG_SERIAL.print(_separator);
  DBG_SERIAL.println(assertStr);

  return false;
}

bool __dbg_assert(bool test, const char *assertStr, const __FlashStringHelper *funcOrFile,
    const unsigned int lineno) {

  if (test) {
    return true; // Assert succeeded.
  }

  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.print(FPSTR(_assert_fail_msg));
  DBG_SERIAL.print(funcOrFile);
  DBG_SERIAL.print('(');
  DBG_SERIAL.print(lineno, DEC);
  DBG_SERIAL.print(_separator);
  DBG_SERIAL.println(assertStr);

  return false;
}

bool __dbg_assert(bool test, const __FlashStringHelper *assertStr, const char *funcOrFile,
    const unsigned int lineno) {

  if (test) {
    return true; // Assert succeeded.
  }

  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.print(FPSTR(_assert_fail_msg));
  DBG_SERIAL.print(funcOrFile);
  DBG_SERIAL.print('(');
  DBG_SERIAL.print(lineno, DEC);
  DBG_SERIAL.print(_separator);
  DBG_SERIAL.println(assertStr);

  return false;
}

bool __dbg_assert(bool test, const __FlashStringHelper *assertStr, const __FlashStringHelper *funcOrFile,
    const unsigned int lineno) {

  if (test) {
    return true; // Assert succeeded.
  }

  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.print(FPSTR(_assert_fail_msg));
  DBG_SERIAL.print(funcOrFile);
  DBG_SERIAL.print('(');
  DBG_SERIAL.print(lineno, DEC);
  DBG_SERIAL.print(_separator);
  DBG_SERIAL.println(assertStr);

  return false;
}


void __dbg_trace(const char *tracemsg, const char *funcOrFile, const uint16_t lineno) {
  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.print(funcOrFile);
  DBG_SERIAL.print('(');
  DBG_SERIAL.print(lineno, DEC);
  DBG_SERIAL.print(_separator);
  DBG_SERIAL.println(tracemsg);
}

void __dbg_trace(const char *tracemsg, const __FlashStringHelper *funcOrFile, const uint16_t lineno) {
  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.print(funcOrFile);
  DBG_SERIAL.print('(');
  DBG_SERIAL.print(lineno, DEC);
  DBG_SERIAL.print(_separator);
  DBG_SERIAL.println(tracemsg);
}

void __dbg_trace(const __FlashStringHelper *tracemsg, const char *funcOrFile, const uint16_t lineno) {
  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.print(funcOrFile);
  DBG_SERIAL.print('(');
  DBG_SERIAL.print(lineno, DEC);
  DBG_SERIAL.print(_separator);
  DBG_SERIAL.println(tracemsg);
}

void __dbg_trace(const __FlashStringHelper *tracemsg, const __FlashStringHelper *funcOrFile,
    const uint16_t lineno) {

  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.print(funcOrFile);
  DBG_SERIAL.print('(');
  DBG_SERIAL.print(lineno, DEC);
  DBG_SERIAL.print(_separator);
  DBG_SERIAL.println(tracemsg);
}

void __dbg_print(const char *message) {
  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.println(message);
}

void __dbg_print(const __FlashStringHelper *message) {
  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.println(message);
}

void __dbg_print(bool msg) {
  DBG_SERIAL.print(DBG_RET_PRINT);
  if (msg) {
    DBG_SERIAL.println(F("true"));
  } else {
    DBG_SERIAL.println(F("false"));
  }
}

void __dbg_print(uint8_t msg) {
  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.println(msg, DEC);
}

void __dbg_print(int msg) {
  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.println(msg, DEC);
}

void __dbg_print(long msg) {
  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.println(msg, DEC);
}

void __dbg_print(unsigned int msg) {
  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.println(msg, DEC);
}

void __dbg_print(unsigned long msg) {
  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.println(msg, DEC);
}

void __dbg_break(const char *funcOrFile, const uint16_t lineno) {
  debug_status |= DBG_STATUS_IN_BREAK; // Mark debugger as started so we don't recursively re-enter.
  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.print(FPSTR(_breakpoint_msg));
  DBG_SERIAL.print(funcOrFile);
  DBG_SERIAL.print(':');
  DBG_SERIAL.print(' ');
  DBG_SERIAL.println(lineno, DEC);

#ifndef DBG_NO_STACKTRACE
  // Top of stack trace was captured on entry into this method.
  // Don't take a final reading of PC.
  pcAtBreakpoint = NULL;
#endif /* DBG_NO_STACKTRACE */

  __dbg_service();
}

void __dbg_break(const __FlashStringHelper *funcOrFile, const uint16_t lineno) {
  debug_status |= DBG_STATUS_IN_BREAK; // Mark debugger as started so we don't recursively re-enter.
  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.print(FPSTR(_breakpoint_msg));
  DBG_SERIAL.print(funcOrFile);
  DBG_SERIAL.print(':');
  DBG_SERIAL.print(' ');
  DBG_SERIAL.println(lineno, DEC);

#ifndef DBG_NO_STACKTRACE
  // Top of stack trace was captured on entry into this method.
  // Don't take a final reading of PC.
  pcAtBreakpoint = NULL;
#endif /* DBG_NO_STACKTRACE */

  __dbg_service();
}

//                   *** Call stack tracing ***
//
// We need to record our own stack of calls since we can't walk the real stack frames on
// AVR.  This is stored in a circular buffer, updated using profiling hooks on method
// entry & exit.  If the call stack depth ever exceeds the size of traceStack, we continue
// to record deeper stack frames, dropping shallower ones (on the theory that most
// debugging is deep in the core, and you're unlikely to care about `main()` itself, or
// the other shallow method calls).
//
// This can be controlled with DBG_MAX_STACK_FRAMES, although we put a hard cap @ 64 for
// sanity.
//
// For this to work, you must compile your code with -finstrument-functions.
//
// This does *not* memoize any methods defined with the `no_instrument_function`
// attribute. We also configure (via gcc args) the Arduino core to be exempt from tracing.
// And since libc wasn't compiled with tracing hooks enabled, it is also exempt; thus this
// tracks method calls in user code & added libraries only.
//
// As a complicated wrinkle to the above point about instrumentation: Our method actually
// logs the PC at the *caller* of the method, not the method we're jumping into. The breakpoint
// logic captures the PC within the interrupted method regardless of whether that method is
// instrumented.

#ifndef DBG_NO_STACKTRACE // Stack-tracing enabled.

#ifdef DBG_ENABLED
// traceStack holds addresses of instrumented functions we enter.
static volatile void* traceStack[__dbg_internal_stack_frame_limit];
static volatile void** traceStackNext = &(traceStack[0]);
static volatile void** traceStackTop = NULL;

// the companion callerStack holds return addresses into callers captured
// simultaneously when we put a top-of-function addr on traceStack.
static volatile void* callerStack[__dbg_internal_stack_frame_limit];
static volatile void** callerStackNext = &(callerStack[0]);
// We don't need a 'Top' pointer here b/c the cursor moves in sync with
// traceStackNext; we know when to roll around to the other end of the array.
#endif

void __cyg_profile_func_enter(void *this_fn, void *call_site) {
#ifdef DBG_ENABLED // If we're compiling dbg in degenerate mode, avoid fn-call overhead.
  uint8_t SREG_old = SREG;
  cli(); // Disable interrupts during logging.

  if (traceStackNext == traceStackTop) {
    // We're about to overwrite the current top-of-stack entry because we wrapped.
    // Forget top-of-stack by kicking 'top' down a level.
    traceStackTop++;
    if (traceStackTop > &(traceStack[__dbg_internal_stack_frame_limit - 1])) {
      // Wrap 'top' back around.
      traceStackTop = &(traceStack[0]);
    }
  }

  // Use return site into *our* caller as stand-in for this_fn; generates smaller code
  // when creating calls to __cyg_profile_func_enter() while still identifying the
  // entered function correctly.
  *traceStackNext = __builtin_extract_return_addr(__builtin_return_address(0)); // this_fn;
  *callerStackNext = call_site;

  if (NULL == traceStackTop) {
    traceStackTop = traceStackNext; // Non-empty buffer now has a top-of-stack.
  }

  traceStackNext++;
  callerStackNext++;
  if (traceStackNext > &(traceStack[__dbg_internal_stack_frame_limit - 1])) {
    // wrap around. Next call will eat an earlier stacktrace element.
    traceStackNext = &(traceStack[0]);
    callerStackNext = &(callerStack[0]);
  }

  SREG = SREG_old; // Restore prior interrupt flag status.
#endif /* DBG_ENABLED */
}

void __cyg_profile_func_exit(void *this_fn, void *call_site) {
#ifdef DBG_ENABLED
  uint8_t SREG_old = SREG;
  cli();

  if (traceStackNext != &(traceStack[0])) {
    // We're forgetting the bottom-most call on the call stack.
    // Throw away one pointer level.
    traceStackNext--;
    callerStackNext--;
  } else {
    // The bottom-most call stack is in the first slot of the ring buffer.
    // Point to the last slot of the ring buffer instead.
    traceStackNext = &(traceStack[__dbg_internal_stack_frame_limit - 1]);
    callerStackNext = &(callerStack[__dbg_internal_stack_frame_limit - 1]);
  }

  if (traceStackNext == traceStackTop) {
    // We evicted the top-of-stack call. The ring buffer is now empty.
    traceStackTop = NULL;
  }

  SREG = SREG_old;
#endif /* DBG_ENABLED */
}


static inline void __dbg_callstack_epilogue() __attribute__((no_instrument_function));
/** Clean-up code to call on all exit paths from __dbg_callstack(). */
static inline void __dbg_callstack_epilogue() {
  DBG_SERIAL.println('$');
}

/**
 * Enumerate the methods on the call stack.
 *
 * This does not walk the stack directly (not possible on AVR); it just prints the values
 * logged by the "profiling" functions that have been maintaining a separate
 * function-pointer stack in a circular buffer.
 */
static void __dbg_callstack() {
  uint16_t fnPtr;

  // The very top of the callstack is the PC running before we hit the ISR.
  // This is stored in its own variable off the instrumented stack.
  // (This will be NULL if we entered this through an instrumented DBG_BREAK() call.)
  // Either way, send back as top-most frame.
  fnPtr = (uint16_t)pcAtBreakpoint;
#ifdef __AVR_ARCH__
  fnPtr <<= 1; // Function pointer values on AVR must mul by 2 to relate to .text section.
#endif /* __AVR_ARCH__ */
  DBG_SERIAL.println(fnPtr, HEX);

  if (NULL == traceStackTop) {
    // Empty call stack traced. Nothing more to report.
    return __dbg_callstack_epilogue();
  }

  volatile void **traceElem = traceStackNext - 1;
  volatile void **callerElem = callerStackNext - 1;
  if (traceElem < &(traceStack[0])) {
    traceElem = &(traceStack[__dbg_internal_stack_frame_limit - 1]);
    callerElem = &(callerStack[__dbg_internal_stack_frame_limit - 1]);
  }

  while(true) {
    // Alternate between reporting elements of traceStack and callerStack to
    // allow the client to reproduce as much of the call stack as possible.
    // Deduplication is caller's responsibility since we lack the symbol detail
    // data here to perform that job (specifically, we need to know the size of
    // each method in bytes).
    fnPtr = (uint16_t)*traceElem;
#ifdef __AVR_ARCH__
    fnPtr <<= 1; // Function pointer values on AVR must mul by 2 to relate to .text section.
#endif /* __AVR_ARCH__ */

    DBG_SERIAL.println(fnPtr, HEX);

    fnPtr = (uint16_t)*callerElem;
#ifdef __AVR_ARCH__
    fnPtr <<= 1; // Function pointer values on AVR must mul by 2 to relate to .text section.
#endif /* __AVR_ARCH__ */

    DBG_SERIAL.println(fnPtr, HEX);

    if (traceElem == traceStackTop) {
      break;
    }

    traceElem--;
    callerElem--;
    if (traceElem < &(traceStack[0])) {
      traceElem = &(traceStack[__dbg_internal_stack_frame_limit - 1]);
      callerElem = &(callerStack[__dbg_internal_stack_frame_limit - 1]);
    }
  }

  return __dbg_callstack_epilogue();
}

#else /* DBG_NO_STACKTRACE */

static void __dbg_callstack() {
  // Stack tracing disabled; respond with empty stack.
  DBG_SERIAL.println('$');
}

#endif /* DBG_NO_STACKTRACE */


/**
 * 1Hz timer fires for us to check whether data is available on DBG_SERIAL port.
 * If we have a request from the debugger client, we break into the debugger service.
 */
ISR(TIMER1_COMPA_vect) {
  if (!(debug_status & DBG_STATUS_IN_BREAK) && DBG_SERIAL.available()) {
    // Enter debug service if serial traffic available, and we are not already within the dbg
    // service.
#ifndef DBG_NO_STACKTRACE
    // But first, record the top of the stacktrace (where this ISR would RETI back to)
    pcAtBreakpoint = __builtin_extract_return_addr(__builtin_return_address(0));
#endif /* DBG_NO_STACKTRACE */
    __dbg_service();
  }
}
