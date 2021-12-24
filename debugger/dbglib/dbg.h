// (c) Copyright 2021 Aaron Kimball
//
// dbg.h - Add debugger support to your Arduino sketch
//
// To enable the debugging system, use the following three steps:
//
// 1) include `dbg` in your  Makefile's `libs` list variable.
// 2) #include <dbg.h>
// 3) replace the words `void setup()` in your sketch with `SETUP()`. e.g.:
//
//     SETUP() {
//       /* your setup function. */
//     }
//
// You can control this library by defining the following macros before dbg.h is #include'd:
//
// * NDEBUG: Debugger support is suppressed.
// * DEBUG: Debugger support is explicitly enabled (overrides NDEBUG).
//
// * DBG_PRETTY_FUNCTIONS: Use pretty-printed function names in ASSERT() and TRACE().
//   Without it, the filename (via __FILE__ macro) will be used instead. Function names will
//   consume RAM whereas filenames are stored in Flash via the `F()` macro.
// * DBG_START_PAUSED: The sketch will immediately enter the debugger and require
//   an explicit 'continue' ('C') command before proceeding to your setup() fn.
// * DBG_WAIT_FOR_CONNECT: The sketch will wait for a Serial connection before
//   beginning. (On supported systems - Arduino Leonardo.)
//

#ifndef _DBG_H
#define _DBG_H

#if defined(NDEBUG) && defined(DEBUG)
/* DEBUG conquors NDEBUG. */
#undef NDEBUG
#endif /* NDEBUG && DEBUG */

#ifdef NDEBUG
// Suppress debugger support.

#define SETUP() void setup()
#define BREAK()
#define ASSERT(x)
#define TRACE(x)
#define DBGPRINT(x)

#else
// Debugger support enabled.

#include<Arduino.h> // for typedefs e.g. uint8_t

extern void __dbg_setup();

extern void __dbg_break(const char *funcOrFile, const uint16_t lineno); /* Enter user breakpoint. */
extern void __dbg_break(const String &funcOrFile, const uint16_t lineno);

extern bool __dbg_assert(bool test, const String &assertStr, const String &funcOrFile,
    const unsigned int lineno);

inline bool __dbg_assert(uint8_t test, const String &assertStr, const String &funcOrFile,
    const uint16_t lineno) {
  __dbg_assert(test != 0, assertStr, funcOrFile, lineno);
  return test;
}

inline bool __dbg_assert(int test, const String &assertStr, const String &funcOrFile,
    const uint16_t lineno) {
  __dbg_assert(test != 0, assertStr, funcOrFile, lineno);
  return test;
}

inline bool __dbg_assert(long test, const String &assertStr, const String &funcOrFile,
    const uint16_t lineno) {
  __dbg_assert(test != 0, assertStr, funcOrFile, lineno);
  return test;
}

inline bool __dbg_assert(unsigned int test, const String &assertStr, const String &funcOrFile,
    const uint16_t lineno) {
  __dbg_assert(test != 0, assertStr, funcOrFile, lineno);
  return test;
}

inline bool __dbg_assert(unsigned long test, const String &assertStr, const String &funcOrFile,
    const uint16_t lineno) {
  __dbg_assert(test != 0, assertStr, funcOrFile, lineno);
  return test;
}

inline bool __dbg_assert(void *test, const String &assertStr, const String &funcOrFile,
    const uint16_t lineno) {
  __dbg_assert(test != 0, assertStr, funcOrFile, lineno);
  return test;
}

extern void __dbg_print(const char *message);
extern void __dbg_print(const String &msg);
extern void __dbg_print(bool msg);
extern void __dbg_print(uint8_t msg);
extern void __dbg_print(int msg);
extern void __dbg_print(long msg);
extern void __dbg_print(unsigned int msg);
extern void __dbg_print(unsigned long msg);

extern void __dbg_trace(const String &tracemsg, const String &funcOrFile, const uint16_t lineno);


#ifdef DBG_PRETTY_FUNCTIONS
#  define ASSERT(x) __dbg_assert(x, F(#x), __PRETTY_FUNCTION__, __LINE__)
#  define TRACE(x) __dbg_trace(F(#x),  __PRETTY_FUNCTION__, __LINE__)
#  define BREAK() __dbg_break(__PRETTY_FUNCTION__, __LINE__);
#else
#  define ASSERT(x) __dbg_assert(x, F(#x), F(__FILE__), __LINE__)
#  define TRACE(x) __dbg_trace(F(#x),  F(__FILE__), __LINE__)
#  define BREAK() __dbg_break(F(__FILE__), __LINE__);
#endif /* DBG_PRETTY_FUNCTIONS */


#ifdef DBG_START_PAUSED
// Within the SETUP() macro, start paused immediately prior to user's setup().
#  define __optional_immediate_brk() { DBGPRINT("Break on init"); BREAK(); }
#else
#  define __optional_immediate_brk()
#endif /* DBG_START_PAUSED */

#ifdef __AVR_ATmega32U4__
// Arduino Leonardo -- require serial.
#  define WAIT_FOR_CONNECT_SUPPORTED  1
#else
#  define WAIT_FOR_CONNECT_SUPPORTED  0
#endif /* __AVR_ATmega32U4__ */

#if WAIT_FOR_CONNECT_SUPPORTED == 1 && defined(DBG_WAIT_FOR_CONNECT)
#  define __optional_wait_for_conn()  while (!Serial) { delay(1); };
#else
#  define __optional_wait_for_conn()
#endif /* DBG_WAIT_FOR_CONNECT ? */


#define SETUP() \
    static void __user_setup(); /* fwd declare. */ \
    void setup() {                          \
      __dbg_setup();                        \
      __optional_wait_for_conn();           \
      __optional_immediate_brk();           \
      __user_setup();                       \
    }                                       \
    /* user's code starts below. */         \
    static void __user_setup()

#define DBGPRINT(x) __dbg_print(x)

#endif /* NDEBUG */



#endif /* _DBG_H */
