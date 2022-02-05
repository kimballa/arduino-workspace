// (c) Copyright 2021 Aaron Kimball
//
// Macros to perform blocking delay for sub-microsecond intervals.
// The delay macros here are defined in terms of the chip's clock speed. They will delay for
// *at least* the requisite length of time, and attempt to delay for as little
// more than that as necessary.
//
// The delayMicroseconds() function performs reliably at 3us through tens of microseconds.
// You should use combinations of these macros for shorter time intervals.
//
// Note that the precision of these macros is based on clock speed (see the F_CPU macro).
// e.g., on a 16 MHz CPU, 1 cycle = 62.5 ns so all delays are in multiples of this time.
//
// These macros do not disable interrupts. You should execute the `CLI` and `SEI`
// instructions yourself before invoking one of these delays if required.
//
// The defined macros are:
//   MICRO_WAIT()        --   1us delay
//   HALF_MICRO_WAIT()   -- 500ns delay
//   EIGHTH_MICRO_WAIT() -- 125ns delay

#ifndef _NANO_DELAY_H
#define _NANO_DELAY_H

#include<Arduino.h>

#if !defined(_NOP) && defined(ARDUINO_ARCH_SAMD)
#define _NOP() { asm("mov r0, r0\n\t"); }
#endif /* No _NOP() and arch == SAMD */

// Building on the _NOP() macro from AVR or Arduino, define multi-NOP sequences.
#define NOP2() _NOP(); _NOP();
#define NOP3() _NOP(); _NOP(); _NOP();
#define NOP4() NOP2(); NOP2();
#define NOP5() NOP4(); _NOP();
#define NOP6() NOP4(); NOP2();
#define NOP7() NOP4(); NOP3();
#define NOP8() NOP4(); NOP4();
#define NOP9() NOP4(); NOP5();
#define NOP10() NOP5(); NOP5();
#define NOP11() NOP6(); NOP5();
#define NOP12() NOP6(); NOP6();
#define NOP13() NOP7(); NOP6();
#define NOP14() NOP7(); NOP7();
#define NOP15() NOP7(); NOP8();
#define NOP16() NOP8(); NOP8();

// For NOP sequences longer than 16, don't inline it all; use a loop.
// The loop contains n/4 runs of a single NOP, allowing 1 cycle for SUBI and 2 for BRNE in loop.
// The loop is written in asm to prevent unrolling, and is equivalent to:
//    for(uint8_t i = 0; i < n/4; i++) { _NOP(); };
// An extra NOP is added at the end because BRNE is only 1 cycle in last-loop condition.
// We then add on NOPs to account for integer rounding when dividing by 4.
#define NOPn(n) do { \
    __asm__ volatile(            \
    "ldi r24, lo8(%0)\n\t"       \
    "NOPL_%=:\n\t"               \
    "nop\n\t"                    \
    "subi r24,lo8(-(-1))\n\t"    \
    "brne NOPL_%=\n\t"           \
    "nop\n\t"                    \
    :                            \
    : "M" (n/4)                  \
    : "r24");                    \
    /* branch-free post-loop padding NOPs to compensate integer division rounding,     \
     * relying on constant-folding and dead-code-elimination optimizations in -Os      \
     * to replace the `if`-based branching structure with the correct NOP sequence. */ \
    if (n % 4 == 3)      { NOP3(); } \
    else if (n % 4 == 2) { NOP2(); } \
    else if (n % 4 == 1) { _NOP(); } \
    } while(0);

// 1us delay : MICRO_WAIT()
#define MICROSEC_CYCLES (clockCyclesPerMicrosecond())

#if MICROSEC_CYCLES < 2
#define MICRO_WAIT() _NOP()
#elif MICROSEC_CYCLES == 2
#define MICRO_WAIT() NOP2()
#elif MICROSEC_CYCLES == 3
#define MICRO_WAIT() NOP3()
#elif MICROSEC_CYCLES == 4
#define MICRO_WAIT() NOP4()
#elif MICROSEC_CYCLES == 5
#define MICRO_WAIT() NOP5()
#elif MICROSEC_CYCLES == 6
#define MICRO_WAIT() NOP6()
#elif MICROSEC_CYCLES == 7
#define MICRO_WAIT() NOP7()
#elif MICROSEC_CYCLES == 8
#define MICRO_WAIT() NOP8()
#elif MICROSEC_CYCLES == 9
#define MICRO_WAIT() NOP9()
#elif MICROSEC_CYCLES == 10
#define MICRO_WAIT() NOP10()
#elif MICROSEC_CYCLES == 11
#define MICRO_WAIT() NOP11()
#elif MICROSEC_CYCLES == 12
#define MICRO_WAIT() NOP12()
#elif MICROSEC_CYCLES == 13
#define MICRO_WAIT() NOP13()
#elif MICROSEC_CYCLES == 14
#define MICRO_WAIT() NOP14()
#elif MICROSEC_CYCLES == 15
#define MICRO_WAIT() NOP15()
#elif MICROSEC_CYCLES == 16
#define MICRO_WAIT() NOP16()
#else
#define MICRO_WAIT() NOPn(MICROSEC_CYCLES)
#endif


// 0.5us delay : HALF_MICRO_WAIT()
#define HALF_MICRO_CYCLES (clockCyclesPerMicrosecond() / 2)

#if HALF_MICRO_CYCLES < 2
#define HALF_MICRO_WAIT() _NOP()
#elif HALF_MICRO_CYCLES == 2
#define HALF_MICRO_WAIT() NOP2()
#elif HALF_MICRO_CYCLES == 3
#define HALF_MICRO_WAIT() NOP3()
#elif HALF_MICRO_CYCLES == 4
#define HALF_MICRO_WAIT() NOP4()
#elif HALF_MICRO_CYCLES == 5
#define HALF_MICRO_WAIT() NOP5()
#elif HALF_MICRO_CYCLES == 6
#define HALF_MICRO_WAIT() NOP6()
#elif HALF_MICRO_CYCLES == 7
#define HALF_MICRO_WAIT() NOP7()
#elif HALF_MICRO_CYCLES == 8
#define HALF_MICRO_WAIT() NOP8()
#elif HALF_MICRO_CYCLES == 9
#define HALF_MICRO_WAIT() NOP9()
#elif HALF_MICRO_CYCLES == 10
#define HALF_MICRO_WAIT() NOP10()
#elif HALF_MICRO_CYCLES == 11
#define HALF_MICRO_WAIT() NOP11()
#elif HALF_MICRO_CYCLES == 12
#define HALF_MICRO_WAIT() NOP12()
#elif HALF_MICRO_CYCLES == 13
#define HALF_MICRO_WAIT() NOP13()
#elif HALF_MICRO_CYCLES == 14
#define HALF_MICRO_WAIT() NOP14()
#elif HALF_MICRO_CYCLES == 15
#define HALF_MICRO_WAIT() NOP15()
#elif HALF_MICRO_CYCLES == 16
#define HALF_MICRO_WAIT() NOP16()
#else
#define HALF_MICRO_WAIT() NOPn(HALF_MICRO_CYCLES)
#endif



// 0.125us delay : EIGHTH_MICRO_WAIT()
// (On a 16 MHz AVR CPU, this is 2 cycles exactly.)
#define EIGHTH_MICRO_CYCLES (clockCyclesPerMicrosecond() / 2)

#if EIGHTH_MICRO_CYCLES < 2
#define EIGHTH_MICRO_WAIT() _NOP()
#elif EIGHTH_MICRO_CYCLES == 2
#define EIGHTH_MICRO_WAIT() NOP2()
#elif EIGHTH_MICRO_CYCLES == 3
#define EIGHTH_MICRO_WAIT() NOP3()
#elif EIGHTH_MICRO_CYCLES == 4
#define EIGHTH_MICRO_WAIT() NOP4()
#elif EIGHTH_MICRO_CYCLES == 5
#define EIGHTH_MICRO_WAIT() NOP5()
#elif EIGHTH_MICRO_CYCLES == 6
#define EIGHTH_MICRO_WAIT() NOP6()
#elif EIGHTH_MICRO_CYCLES == 7
#define EIGHTH_MICRO_WAIT() NOP7()
#elif EIGHTH_MICRO_CYCLES == 8
#define EIGHTH_MICRO_WAIT() NOP8()
#elif EIGHTH_MICRO_CYCLES == 9
#define EIGHTH_MICRO_WAIT() NOP9()
#elif EIGHTH_MICRO_CYCLES == 10
#define EIGHTH_MICRO_WAIT() NOP10()
#elif EIGHTH_MICRO_CYCLES == 11
#define EIGHTH_MICRO_WAIT() NOP11()
#elif EIGHTH_MICRO_CYCLES == 12
#define EIGHTH_MICRO_WAIT() NOP12()
#elif EIGHTH_MICRO_CYCLES == 13
#define EIGHTH_MICRO_WAIT() NOP13()
#elif EIGHTH_MICRO_CYCLES == 14
#define EIGHTH_MICRO_WAIT() NOP14()
#elif EIGHTH_MICRO_CYCLES == 15
#define EIGHTH_MICRO_WAIT() NOP15()
#elif EIGHTH_MICRO_CYCLES == 16
#define EIGHTH_MICRO_WAIT() NOP16()
#else
#define EIGHTH_MICRO_WAIT() NOPn(EIGHTH_MICRO_CYCLES)
#endif

#endif /* _NANO_DELAY_H */
