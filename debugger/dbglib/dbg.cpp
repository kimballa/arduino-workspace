// (C) Copyright 2021 Aaron Kimball

#include "dbg.h"
#include <Stream.h>

/** Declarations and macros from other compilation units */

#ifndef FPSTR
  #define FPSTR(pstr_pointer) (reinterpret_cast<const __FlashStringHelper *>(pstr_pointer))
#endif /* FPSTR */

#ifdef ARDUINO_ARCH_SAMD
  // Symbols needed for memory usage printing.
  extern "C" char *sbrk(int i);
  extern "C" unsigned int __bss_end__; // symbols defined in linker script.
#endif /* SAMD */


/** Forward declarations needed later in this file **/
extern "C" {
  static void __dbg_service(const uint8_t bp_num, uint16_t *breakpoint_flags, uint32_t hw_addr)
      __attribute__((no_instrument_function));

  static inline void __dbg_reset() __attribute__((no_instrument_function));
}

#if defined (__AVR_ARCH__)
  // AVR: Forward-declare ISR function used for Timer1 interrupts for USB activity check.
  ISR(TIMER1_COMPA_vect) __attribute__((no_instrument_function));
#endif /* AVR */

/** Debugger status bits **/
volatile uint8_t debug_status = 0;
static inline void _set_dbg_status(uint8_t new_status) {
  debug_status = new_status;
  #if defined (ARDUINO_ARCH_SAMD)
    // Ensure synchronization of the debug status to prevent debugger service from
    // interrupting itself.
    __DMB();
  #endif /* ARCH_SAMD */
}

#define DBG_STATUS_IN_BREAK     (0x1)  // True if we are inside the debugger service.
#define DBG_STATUS_HARD_BKPT    (0x2)  // True if a hardware BKPT triggered the debugger service.
#define DBG_STATUS_DEBUG_MON_EN (0x4)  // True if we've enabled the onboard debug monitor (SAMD51).
#define DBG_STATUS_STEP_BKPT    (0x8)  // True if a single-step triggered debugging.

#if defined (ARDUINO_ARCH_SAMD)
  // This device supports monitor-mode debugging of hardware breakpoints.
  static constexpr uint8_t _hw_bkpt_supported = 1;
#else
  static constexpr uint8_t _hw_bkpt_supported = 0;
#endif /* Arch select */

/** Debugger wire protocol definition **/

// Version of debugger wire protocol implemented by this library.
static constexpr uint8_t DBG_PROTOCOL_VER = 1;

// The debugger client sends sentences beginning with a DBG_OP_ and ending with DBG_END.
// The sentences may usually contain one or more whitespace-delimited base-10 integer arguments.
// Our commands do not use [0-9] so any extra args are consumed harmlessly rather than be
// accidentally interpreted as other commands.
#define DBG_END          '\n' // end of debugger sentence.

#define DBG_OP_RAMADDR   '@' // Return data at RAM address
#define DBG_OP_STACKREL  '$' // Return data at addr relative to SP.
#define DBG_OP_BREAK     'B' // Break execution of the program. (Redundant if within server)
#define DBG_OP_CONTINUE  'C' // Continue execution.
#define DBG_OP_FLASHADDR 'f' // Return data at Flash address.
#define DBG_OP_SET_FLAG  'L' // Set bit flag in int high or low.
#define DBG_OP_POKE      'K' // Insert data to RAM address.
#define DBG_OP_MEMSTATS  'm' // Describe memory usage.
#define DBG_OP_PORT_IN   'p' // Read gpio pin.
#define DBG_OP_PORT_OUT  'P' // write gpio pin.
#define DBG_OP_RESET     'R' // Reset CPU.
#define DBG_OP_STEP      'S' // Single-step execution.
#define DBG_OP_REGISTERS 'r' // Dump registers.
#define DBG_OP_TIME      't' // Return cpu timekeeping info.
#define DBG_OP_NONE      DBG_END

#define DBG_RET_PRINT    ('>') // prefix for logged messages that debugger client
                               // should output verbatim to console.

// Character appended to 't' (OP_TIME) to specify units to report.
// e.g. Use the command "tm\n" to get the current millis().
#define DBG_TIME_MILLIS 'm' // get time in ms
#define DBG_TIME_MICROS 'u' // get time in us

/** System reset capability **/

#if defined(__AVR_ARCH__)
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

#elif defined(ARDUINO_ARCH_SAMD)

  static inline void __dbg_reset() {
    NVIC_SystemReset(); // CMSIS standard reset option.
  }

#endif /* architecture select */

/** Helpers for timer IRQ definition **/

#if defined(ARDUINO_ARCH_SAMD)

  // Helper fn for timer setup on SAMD architecture.
  // Wait for register changes to sync to underlying device register.
  static inline void TC4_wait_for_sync() {
    while (TC4->COUNT16.SYNCBUSY.reg != 0);
  }

  // Priority level to assign to timer irq for checking for debugger comms.
  // Must be lower priority (higher number) than the priority associated with
  // USBSerial / CDC interface, or else USB will never preempt the debug
  // server. We want to run at a lower priority than any capability we may need
  // within the debugger service. Meaning that we run at the *lowest* priority.
  #define TC4_IRQ_PRIORITY (255)
  #define DebugMon_IRQ_PRIORITY (255)

#endif /* ARDUINO_ARCH_SAMD */

/**
 * Setup function for debugger; called before user's setup function.
 * Activate I/O and IRQs required for debugger operation.
 */
void __dbg_setup() {
  DBG_SERIAL.begin(DBG_SERIAL_SPEED);

  // Set up timer IRQ: 4Hz
  noInterrupts();
  #if defined(__AVR_ARCH__)

    // Set up IRQ on AVR Timer1
    // (see https://www.instructables.com/Arduino-Timer-Interrupts/)
    TCCR1A = 0; // set entire TCCR1A register to 0
    TCCR1B = 0; // same for TCCR1B
    TCNT1  = 0; // initialize counter value to 0
    // set compare match register for 4Hz increments
    // match_register_value = ( F_CPU / (prescaler * target_interrupt_freq_hz) ) - 1
    OCR1A = ((F_CPU) / (4 * 1024)) - 1; // (16*10^6) / (4*1024) - 1 = 3905 (must be <65536)
    TCCR1B |= (1 << WGM12); // turn on CTC mode
    // Set CS10 and CS12 bits for 1024 prescaler
    TCCR1B |= (1 << CS12) | (1 << CS10);
    // enable timer compare interrupt
    TIMSK1 |= (1 << OCIE1A);

  #elif defined(ARDUINO_ARCH_SAMD)

    // Set up 4Hz timer on ARM/SAMD.
    // Code based on github.com/Dennis-van-Gils/SAMD51_InterruptTimer

    // base clocks set up in cores/arduino/startup.c
    // GCLK1: 48 MHz
    // with prescaler of 1024, count from [0, 46875) in one second. 4 Hz (250ms) => TOP=11718
    // Configure TC4 to track GCLK1, and use TC4 in compare/match mode to its CC0 register.
    constexpr uint32_t GCLK1_HZ = 48000000;
    constexpr uint32_t TIMER_PRESCALER = 1024;
    constexpr uint32_t freq = 4; // 4 Hz.

    GCLK->PCHCTRL[TC4_GCLK_ID].reg = GCLK_PCHCTRL_GEN_GCLK1_Val | (1 << GCLK_PCHCTRL_CHEN_Pos);
    while (GCLK->SYNCBUSY.reg > 0); // Wait for clock register sync
    TC4->COUNT16.CTRLA.bit.ENABLE = 0; // EN must be low to modify register.
    TC4->COUNT16.WAVE.bit.WAVEGEN = TC_WAVE_WAVEGEN_MFRQ; // mode: "match freq"; TOP=CC0.
    TC4_wait_for_sync();

    // Set priority and enable compare interrupt
    NVIC_ClearPendingIRQ(TC4_IRQn); // If a TC4 interrupt was already queued up, ignore it.
    NVIC_SetPriority(TC4_IRQn, TC4_IRQ_PRIORITY); // Cortex-M0 requires priority set before enable
    TC4->COUNT16.INTENSET.reg = 0;
    TC4->COUNT16.INTENSET.bit.MC0 = 1; // IRQ for match-compare mode vs CC0 comparator register.
    NVIC_EnableIRQ(TC4_IRQn); // Enable IRQ (TC4_Handler())

    // Set period.
    TC4->COUNT16.CTRLA.reg &= ~TC_CTRLA_ENABLE;
    TC4_wait_for_sync();
    // Enable 1024 prescaler. (All prescaler select bits set high.)
    TC4->COUNT16.CTRLA.reg |= TC_CTRLA_PRESCALER_DIV1024;
    TC4_wait_for_sync();

    constexpr uint16_t TOP = (uint16_t)((GCLK1_HZ / (TIMER_PRESCALER * freq)) - 1); // TOP=11718.
    TC4->COUNT16.COUNT.reg = 0;    // Reset counter.
    TC4->COUNT16.CC[0].reg = TOP;  // Set trigger count.
    TC4_wait_for_sync();

    // All systems go.
    TC4->COUNT16.CTRLA.bit.ENABLE = 1;
    TC4_wait_for_sync();

    // Set up "monitor-mode" debugging--if we encounter a BKPT instruction, trigger
    // our own exception handler rather than hardware-halting for a JTAG debugger to probe.
    // See https://interrupt.memfault.com/blog/cortex-m-debug-monitor
    if (CoreDebug->DHCSR & CoreDebug_DHCSR_C_DEBUGEN_Msk) {
      // DHCSR register bit C_DEBUGEN is set; hardware debugger is attached, and we cannot
      // unset it from software. Warn the attached arduino_dbg that this is the case.
      // (Notwithstanding that this warning may be missed if the usb debugger isn't yet attached.)
      static const char _hardware_debugger_attached_msg[] PROGMEM =
          ">WARNING: hardware debugger is attached; dbg cannot trap BKPT instructions.";
      DBG_SERIAL.println(_hardware_debugger_attached_msg);
    } else {
      // Set DebugMon IRQ priority to lowest priority level; other interrupts may still operate
      // (to ensure USB link remains active).
      NVIC_SetPriority(DebugMonitor_IRQn, DebugMon_IRQ_PRIORITY);

      // Enable DebugMon interrupt.
      CoreDebug->DEMCR |= 1 << CoreDebug_DEMCR_MON_EN_Pos;

      static const char _software_debugger_en_msg[] PROGMEM =
          ">Enabled DebugMon interrupt for onboard software debugger.";
      DBG_SERIAL.println(_software_debugger_en_msg);

      // Mark this as enabled for our own tracking (i.e., to let __dbg_status() know we can operate
      // on hardware breakpoints safely).
      _set_dbg_status(debug_status | DBG_STATUS_DEBUG_MON_EN);
    }

  #endif /* (architecture select) */
  interrupts();
}

// Keyword sent from sketch/server to client whenever breakpoint is triggered (either
// from sketch source code or via interrupt) to let client know we're in the dbg server.
static const char _paused_msg[] PROGMEM = "Paused ";

/**
 * Report to the attached debugger that we are in the Paused state.
 */
static inline void __dbg_report_pause(const uint8_t bp_num,
    const uint16_t *const breakpoint_flags,
    uint32_t hw_addr) {

  // Report pause as: "Paused {dbgver:x} {swFlagNum:x} {swFlagsAddr:x} {hwAddr:x}\n"
  DBG_SERIAL.print(FPSTR(_paused_msg));
  DBG_SERIAL.print(DBG_PROTOCOL_VER, HEX);
  DBG_SERIAL.print(' ');
  DBG_SERIAL.print(bp_num, HEX);
  DBG_SERIAL.print(' ');
  DBG_SERIAL.print((unsigned)breakpoint_flags, HEX);
  DBG_SERIAL.print(' ');
  DBG_SERIAL.println(hw_addr, HEX);
}

/**
 * Consume remaining user input on line.
 * Performed before we leave the __dbg_service(), otherwise the timer interrupt
 * will detect Serial.available() is True and immediately reenter the debug service.
 */
static inline void _eat_remaining_input() {
  // Eat remainder of the line.
  uint8_t b = 0;
  while ((char)b != DBG_END) {
    while (!DBG_SERIAL.available()) { }
    b = DBG_SERIAL.read(); // consume expected EOL marker before debugger exit.
  }
}

/**
 * Called at breakpoint in user code (or via ISR if serial traffic arrives). Starts a service
 * that communicates over DBG_SERIAL about the state of the CPU until released to continue by
 * the client.
 *
 * @param bp_num Represents the SW breakpoint number within its translation unit. Each invocation
 *    of BREAK() has a distinct breakpoint id.
 * @param breakpoint_flags Pointer to breakpoint-enabling flags for the translation unit containing
 *    the SW breakpoint. If the debugger itself invoked a program break, this will be NULL.
 * @param hw_addr The return $PC value associated with a hardware trap / breakpoint that triggered
 *    this breakpoint / debug service.
 */
static void __dbg_service(const uint8_t bp_num, uint16_t *breakpoint_flags, uint32_t hw_addr) {
  // Mark the service as started so we don't recursively re-enter.
  _set_dbg_status(debug_status | DBG_STATUS_IN_BREAK);
  // In order to communicate over UART or USB Serial, we need to keep servicing interrupts within
  // debugger, even if called via IRQ.
  interrupts();
  // TODO(aaron): Give user a way to disable interrupts of theirs via callback SPI before sei?

  static uint8_t cmd;
  __dbg_report_pause(bp_num, breakpoint_flags, hw_addr);

  #ifdef ARDUINO_ARCH_SAMD
    // Clear Debug Fault Status Register (DFSR) bits in System Control Block (SCB).
    static constexpr uint32_t DFSR_TRAP_BITS =
        SCB_DFSR_HALTED_Msk | SCB_DFSR_BKPT_Msk | SCB_DFSR_DWTTRAP_Msk;
    SCB->DFSR &= ~DFSR_TRAP_BITS;  // Clear DWTTRAP, BKPT, HALTED bits.
    // If we ran a single-step instruction, clear the MON_STEP bit of DEMCR register.
    CoreDebug->DEMCR &= ~(1 << CoreDebug_DEMCR_MON_STEP_Pos);
  #endif /* SAMD */

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

    volatile register uint32_t SP asm("sp");
    switch(cmd) {
    case DBG_OP_BREAK:
      __dbg_report_pause(bp_num, breakpoint_flags, hw_addr);
      break;
    case DBG_OP_RESET:
      __dbg_reset();
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
      #if defined(__AVR_ARCH__)

        DBG_SERIAL.println(SP, HEX);
        DBG_SERIAL.println((uint16_t)__malloc_heap_end, HEX);
        DBG_SERIAL.println((uint16_t)__malloc_heap_start, HEX);

      #elif defined(ARDUINO_ARCH_SAMD)

        DBG_SERIAL.println(SP, HEX);
        DBG_SERIAL.println((uint32_t)sbrk(0), HEX);
        DBG_SERIAL.println((uint32_t)(&__bss_end__), HEX);

      #endif /* architecture select */
#endif /* !DBG_NO_MEM_REPORT */
      DBG_SERIAL.println('$');
      break;
    case DBG_OP_REGISTERS:
      #if defined(__AVR_ARCH__)

        // 32 general purpose registers are mem-mapped at 0x00..0x1F (mega32u4 ds fig. 4-2)
        for(addr = 0; addr < 32; addr++) {
          DBG_SERIAL.println(*((uint8_t*)addr), HEX);
        }
        // Special registers: SP (AVR note: 16 bit), SREG
        DBG_SERIAL.println((uint16_t)SP, HEX);
        DBG_SERIAL.println((uint8_t)SREG, HEX);
        // PC can only be read by pushing it to the stack via a 'method call'.
        asm volatile (
            "rcall .    \n\t" // push PC value as of the next instruction point.
            "pop %B0    \n\t" // pop PChi into hi(addr)
            "pop %A0    \n\t" // pop PClo into lo(addr)
        : "=e" (addr)
        );
        DBG_SERIAL.println(addr << 1, HEX); // addr now holds PC[15:1]; lsh by 1 to get a 'real' addr.
        // TODO(aaron): Do we need RAMPX..Z, EIND? See avr/common.h for defs.

      #elif defined(ARDUINO_ARCH_SAMD)

        // 16 general purpose registers, including SP and PC.
        asm volatile ("mov %[out], r0 \n\t" : [out] "=l" (addr));
        DBG_SERIAL.println(addr, HEX);
        asm volatile ("mov %[out], r1 \n\t" : [out] "=l" (addr));
        DBG_SERIAL.println(addr, HEX);
        asm volatile ("mov %[out], r2 \n\t" : [out] "=l" (addr));
        DBG_SERIAL.println(addr, HEX);
        asm volatile ("mov %[out], r3 \n\t" : [out] "=l" (addr));
        DBG_SERIAL.println(addr, HEX);
        asm volatile ("mov %[out], r4 \n\t" : [out] "=l" (addr));
        DBG_SERIAL.println(addr, HEX);
        asm volatile ("mov %[out], r5 \n\t" : [out] "=l" (addr));
        DBG_SERIAL.println(addr, HEX);
        asm volatile ("mov %[out], r6 \n\t" : [out] "=l" (addr));
        DBG_SERIAL.println(addr, HEX);
        asm volatile ("mov %[out], r7 \n\t" : [out] "=l" (addr));
        DBG_SERIAL.println(addr, HEX);
        asm volatile ("mov %[out], r8 \n\t" : [out] "=l" (addr));
        DBG_SERIAL.println(addr, HEX);
        asm volatile ("mov %[out], r9 \n\t" : [out] "=l" (addr));
        DBG_SERIAL.println(addr, HEX);
        asm volatile ("mov %[out], r10 \n\t" : [out] "=l" (addr));
        DBG_SERIAL.println(addr, HEX);
        asm volatile ("mov %[out], r11 \n\t" : [out] "=l" (addr));
        DBG_SERIAL.println(addr, HEX);
        asm volatile ("mov %[out], r12 \n\t" : [out] "=l" (addr));
        DBG_SERIAL.println(addr, HEX);
        asm volatile ("mov %[out], r13 \n\t" : [out] "=l" (addr));
        DBG_SERIAL.println(addr, HEX);
        asm volatile ("mov %[out], r14 \n\t" : [out] "=l" (addr));
        DBG_SERIAL.println(addr, HEX);
        asm volatile ("mov %[out], pc \n\t" : [out] "=l" (addr)); // $pc is r15
        addr &= ~1; // $PC must be short-aligned; disregard lsb (thumb state flag).
        DBG_SERIAL.println(addr, HEX);
        DBG_SERIAL.println(__get_xPSR(), HEX); // Return $xPSR status registers (IPSR/EPSR/APSR) view.
        DBG_SERIAL.println(__get_MSP(), HEX);  // Return Main Stack Pointer ($MSP)
        DBG_SERIAL.println(__get_PSP(), HEX);  // Return Process Stack Pointer ($PSP)

      #endif /* architecture select */
      DBG_SERIAL.println('$');
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
    case DBG_OP_SET_FLAG:
      // Sets a breakpoint bitfield flag to 1 or 0.
      // L <flagNum> <bitFieldAddr> <val>
      offset = DBG_SERIAL.parseInt(LookaheadMode::SKIP_WHITESPACE);
      addr = DBG_SERIAL.parseInt(LookaheadMode::SKIP_WHITESPACE);
      b = DBG_SERIAL.parseInt(LookaheadMode::SKIP_WHITESPACE);
      if (b) {
        // Set it to high.
        *((bp_bitfield_t*) addr) |= (bp_bitfield_t) bit(offset);
      } else {
        // Set it to low.
        *((bp_bitfield_t*) addr) &= ~((bp_bitfield_t) bit(offset));
      }
      break;
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
    case DBG_OP_STEP: // Single-step execution forward by one op.
      #ifdef ARDUINO_ARCH_SAMD
        if (!(debug_status & DBG_STATUS_DEBUG_MON_EN)) {
          // We do not have the debug monitor enabled, and so cannot single-step.
          DBG_SERIAL.print(DBG_RET_PRINT);
          DBG_SERIAL.println(F("Error: Single-step is currently disabled."));
        } else {
          // SAMD51: Set MON_STEP bit in DEMCR register to activate single-step after this IRQ
          // returns.
          CoreDebug->DEMCR |= 1 << CoreDebug_DEMCR_MON_STEP_Pos;
          _eat_remaining_input();
          goto exit_loop; // Leave dbg service; allow instruction execution to occur.
        }
      #else
        // This CPU architecture does not support single-step monitor-mode debugging.
        DBG_SERIAL.print(DBG_RET_PRINT);
        DBG_SERIAL.println(F("Error: Unsupported"));
      #endif
      break;
    case DBG_OP_CONTINUE: // Continue main program execution; exit debugger.
      _eat_remaining_input();
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

  // Mark debug service as closed.
  _set_dbg_status(debug_status & ~DBG_STATUS_IN_BREAK);
}

static const char _breakpoint_msg[] PROGMEM = "Breakpoint at ";
static const char _assert_fail_msg[] PROGMEM = "Assertion failure in ";
static const char _separator[] PROGMEM = "): ";

bool __dbg_assert(const bool test, const char *assertStr, const char *funcOrFile,
    const uint16_t lineno) {

  if (test) {
    return true; // Assert succeeded.
  }

  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.print(FPSTR(_assert_fail_msg));
  DBG_SERIAL.print(funcOrFile);
  DBG_SERIAL.print('(');
  DBG_SERIAL.print(lineno, DEC);
  DBG_SERIAL.print(FPSTR(_separator));
  DBG_SERIAL.println(assertStr);

  return false;
}

bool __dbg_assert(const bool test, const char *assertStr, const __FlashStringHelper *funcOrFile,
    const uint16_t lineno) {

  if (test) {
    return true; // Assert succeeded.
  }

  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.print(FPSTR(_assert_fail_msg));
  DBG_SERIAL.print(funcOrFile);
  DBG_SERIAL.print('(');
  DBG_SERIAL.print(lineno, DEC);
  DBG_SERIAL.print(FPSTR(_separator));
  DBG_SERIAL.println(assertStr);

  return false;
}

bool __dbg_assert(const bool test, const __FlashStringHelper *assertStr, const char *funcOrFile,
    const uint16_t lineno) {

  if (test) {
    return true; // Assert succeeded.
  }

  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.print(FPSTR(_assert_fail_msg));
  DBG_SERIAL.print(funcOrFile);
  DBG_SERIAL.print('(');
  DBG_SERIAL.print(lineno, DEC);
  DBG_SERIAL.print(FPSTR(_separator));
  DBG_SERIAL.println(assertStr);

  return false;
}

bool __dbg_assert(const bool test, const __FlashStringHelper *assertStr,
    const __FlashStringHelper *funcOrFile, const uint16_t lineno) {

  if (test) {
    return true; // Assert succeeded.
  }

  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.print(FPSTR(_assert_fail_msg));
  DBG_SERIAL.print(funcOrFile);
  DBG_SERIAL.print('(');
  DBG_SERIAL.print(lineno, DEC);
  DBG_SERIAL.print(FPSTR(_separator));
  DBG_SERIAL.println(assertStr);

  return false;
}


void __dbg_trace(const char *tracemsg, const char *funcOrFile, const uint16_t lineno) {
  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.print(funcOrFile);
  DBG_SERIAL.print('(');
  DBG_SERIAL.print(lineno, DEC);
  DBG_SERIAL.print(FPSTR(_separator));
  DBG_SERIAL.println(tracemsg);
}

void __dbg_trace(const char *tracemsg, const __FlashStringHelper *funcOrFile, const uint16_t lineno) {
  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.print(funcOrFile);
  DBG_SERIAL.print('(');
  DBG_SERIAL.print(lineno, DEC);
  DBG_SERIAL.print(FPSTR(_separator));
  DBG_SERIAL.println(tracemsg);
}

void __dbg_trace(const __FlashStringHelper *tracemsg, const char *funcOrFile, const uint16_t lineno) {
  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.print(funcOrFile);
  DBG_SERIAL.print('(');
  DBG_SERIAL.print(lineno, DEC);
  DBG_SERIAL.print(FPSTR(_separator));
  DBG_SERIAL.println(tracemsg);
}

void __dbg_trace(const __FlashStringHelper *tracemsg, const __FlashStringHelper *funcOrFile,
    const uint16_t lineno) {

  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.print(funcOrFile);
  DBG_SERIAL.print('(');
  DBG_SERIAL.print(lineno, DEC);
  DBG_SERIAL.print(FPSTR(_separator));
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

void __dbg_break(const uint8_t flag_num, uint16_t* flags,
    const char *funcOrFile, const uint16_t lineno) {

  if (flag_num < _DBG_MAX_BP_FLAGS_PER_FILE && (*flags & bit(flag_num)) == 0) {
    // Breakpoint is disabled by debugger.
    return;
  }

  // Mark debugger as started so we don't recursively re-enter.
  _set_dbg_status(debug_status | DBG_STATUS_IN_BREAK);
  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.print(FPSTR(_breakpoint_msg));
  DBG_SERIAL.print(funcOrFile);
  DBG_SERIAL.print(':');
  DBG_SERIAL.print(' ');
  DBG_SERIAL.println(lineno, DEC);

  if (_hw_bkpt_supported && debug_status & DBG_STATUS_DEBUG_MON_EN) {
    // We have monitor-mode debugging enabled. Use a "real" breakpoint opcode
    // to shift into the debug monitor irq (and from there to the dbg service).
    // This enables us to enter single-step mode cleanly if desired by the user.
    asm volatile("BKPT \n\t":::"memory");
  } else {
    // Invoke __dbg_service() directly on the thread-mode call stack.
    __dbg_service(flag_num, flags, 0);
  }
}

void __dbg_break(const uint8_t flag_num, uint16_t* flags,
    const __FlashStringHelper *funcOrFile, const uint16_t lineno) {

  if (flag_num < _DBG_MAX_BP_FLAGS_PER_FILE && (*flags & bit(flag_num)) == 0) {
    // Breakpoint is disabled by debugger.
    return;
  }
  // Mark debugger as started so we don't recursively re-enter.
  _set_dbg_status(debug_status | DBG_STATUS_IN_BREAK);
  DBG_SERIAL.print(DBG_RET_PRINT);
  DBG_SERIAL.print(FPSTR(_breakpoint_msg));
  DBG_SERIAL.print(funcOrFile);
  DBG_SERIAL.print(':');
  DBG_SERIAL.print(' ');
  DBG_SERIAL.println(lineno, DEC);

  __dbg_service(flag_num, flags, 0);
}


/**
 * Periodic timer fires for us to check whether data is available on DBG_SERIAL port.
 * If we have a request from the debugger client, we break into the debugger service.
 *
 * Timer frequency & IRQ control initialized in __dbg_setup().
 */
#if defined (__AVR_ARCH__)

  ISR(TIMER1_COMPA_vect) {
    if (!(debug_status & DBG_STATUS_IN_BREAK) && DBG_SERIAL.available()) {
      // Enter debug service if serial traffic available, and we are not already within the dbg
      // service.
      __dbg_service(0, NULL, 0);
    }
  }

#elif defined(ARDUINO_ARCH_SAMD)

	// Immediately before IRQ entry, the following register state is pushed
	// to the stack by hardware.
	typedef struct __attribute__((packed)) _CortexM_IRQ_Frame_s {
		uint32_t r0;
		uint32_t r1;
		uint32_t r2;
		uint32_t r3;
		uint32_t r12;
		uint32_t LR;
		uint32_t PC;
		uint32_t xPSR;
	} CortexM_IRQ_Frame;

  extern "C" void TC4_Handler(void) __attribute__((interrupt, used, no_instrument_function));
  extern "C" void TC4_Handler(void) {
    // Handler can be fired for a variety of timer-related reasons.
    // Filter to continue only based on match-compare to CC0.
    if (TC4->COUNT16.INTFLAG.bit.MC0 != 0) {
      TC4->COUNT16.INTFLAG.bit.MC0 = 1; // Setting bit _clears_ interrupt flag state.
      if (!(debug_status & DBG_STATUS_IN_BREAK) && DBG_SERIAL.available()) {
        // Enter debug service if serial traffic available, and we are not already
        // within the dbg service.
        __dbg_service(0, NULL, 0);
      }
    }
  }

  extern "C" void DebugMon_Handler(void) __attribute__((naked, interrupt, used, no_instrument_function));
  extern "C" void DebugMon_Handler(void) {
    // Handler fired when a debug event occurs (BKPT instruction, or hardware breakpoint/watchpoint)

    // This is a naked ISR. Start with our own prologue that matches what we believe
    // gcc would emit, to eliminate surprises. We want to guarantee our ability to
    // read specific stack data above the current call frame.
    asm volatile (
        ".cfi_def_cfa sp, 0 \n\t"
        "mov   r0, sp       \n\t"
        ".cfi_undefined 0   \n\t" // r0 is clobbered.
        "mov   r12, sp      \n\t"
        ".cfi_undefined 12  \n\t" // r12 is clobbered.
        "bic.w r1, r0, #7   \n\t"
        ".cfi_register 13, 1\n\t" // The "real" $SP is held in r1.
        "mov   sp, r1       \n\t"
        ".cfi_restore 13    \n\t" // $SP holds its own value again.
        // Push everything that might be clobbered in this method, or a callee.
        // $r0 is used to recover entry $SP value, but we don't need to be able to unwind that
        // within this method since it's an ISR-prestacked value.
        // True $LR is also pre-stacked but we need to save the EXN_RETURN status value it currently
        // holds.
        // We also save all other ABI callee-save registers here.
        "push  {r0, r4, r5, r6, r7, r8, r9, r10, fp, lr} \n\t"
        ".cfi_offset 14, -4 \n\t"   // $LR is reg #14; pushed at $entrySP - 4.
        ".cfi_offset 11, -8 \n\t"   // $FP
        ".cfi_offset 10, -12\n\t"   // r10
        ".cfi_offset 9,  -16\n\t"   // r9
        ".cfi_offset 8,  -20\n\t"   // ...
        ".cfi_offset 7,  -24\n\t"
        ".cfi_offset 6,  -28\n\t"
        ".cfi_offset 5,  -32\n\t"
        ".cfi_offset 4,  -36\n\t"
        ".cfi_adjust_cfa_offset 40\n\t" // We pushed 10x4 = 40 bytes to the stack.
    :
    :
    : "memory"                      // Modifies $SP and RAM. Tell gcc not to optimize this.
    );

    volatile register uint32_t SP_entry asm("r12");  // $r12 contains $SP on entry.
                                                     // (Old r12 was already stacked on IRQ entry)
                                                     // This points to a CortexM_IRQ_Frame of data.
    uint32_t return_pc = ((CortexM_IRQ_Frame*)(SP_entry))->PC;

    if (SCB->DFSR & (1 << SCB_DFSR_HALTED_Pos)) {
      // This was triggered by single-stepping.
      _set_dbg_status(debug_status | DBG_STATUS_IN_BREAK | DBG_STATUS_STEP_BKPT);
    } else {
      // We entered this method because of a BKPT instruction (as opposed to after a single-step..)
      //
      // Somewhat uniquely, on entry to this IRQ, BKPT instructions will stack the $pc of
      // the BKPT instruction itself rather than the next $PC. Meaning when we exit this handler,
      // we'll resume execution... right on top of the breakpoint (infinite loop back to here).
      // We need to advance the $PC ourselves.
      ((CortexM_IRQ_Frame*)(SP_entry))->PC += 2;

      // Record that we are in hardware-break status.
      _set_dbg_status(debug_status | DBG_STATUS_IN_BREAK | DBG_STATUS_HARD_BKPT);
    }

    // Invoke __dbg_service() with the return addr from the triggering breakpoint.
    __dbg_service(0, NULL, return_pc);

    // Withdraw from hardware-break status.
    _set_dbg_status(debug_status & ~(DBG_STATUS_IN_BREAK | DBG_STATUS_HARD_BKPT | DBG_STATUS_STEP_BKPT));

    // Hard-coded ISR epilogue.
    asm volatile (
        "ldmia.w sp!, {r0, r4, r5, r6, r7, r8, r9, r10, fp, lr} \n\t"
        ".cfi_register 13, 0        \n\t" // After the POP, the 'real' $SP is in r0.
        ".cfi_restore 14            \n\t" // $LR is restored.
        ".cfi_restore 11            \n\t" // $FP is restored.
        ".cfi_restore 10            \n\t" // r10 is restored, along with other gen-regs...
        ".cfi_restore 9             \n\t"
        ".cfi_restore 8             \n\t"
        ".cfi_restore 7             \n\t"
        ".cfi_restore 6             \n\t"
        ".cfi_restore 5             \n\t"
        ".cfi_restore 4             \n\t"
        ".cfi_adjust_cfa_offset -40 \n\t" // $SP -= 40, is now sitting on its CFA again.
        "mov     sp, r0             \n\t" // $SP fully restored.
        ".cfi_restore 13            \n\t" // $SP is now stored in itself.
        "bx      lr                 \n\t" // Adios! (r0..r3, r12, sp, lr, pc restored in ISR de-stack.)
        "nop                        \n\t"
    :
    :
    : "memory"                      // Full epilogue including return instruction. Force non-opt.
    );
  }
#endif /* architecture select */
