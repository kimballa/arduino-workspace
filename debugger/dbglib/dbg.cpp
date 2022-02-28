// (C) Copyright 2021 Aaron Kimball

#include "dbg.h"
#include <Stream.h>

#ifdef __AVR_ARCH__
#include<avr/boot.h> // For reading signature bytes
#endif /* AVR */

/** Declarations and macros from other compilation units */

#ifndef FPSTR
  #define FPSTR(pstr_pointer) (reinterpret_cast<const __FlashStringHelper *>(pstr_pointer))
#endif /* FPSTR */

#ifdef ARDUINO_ARCH_SAMD
  // Symbols needed for memory usage printing.
  extern "C" char *sbrk(int i);
  extern "C" unsigned int __bss_end__; // symbols defined in linker script.

  // m'mapped FP_CTRL register describing Flash-patch/breakpoint (FPB) unit capabilities.
  // (Not exposed in CMSIS like other mem-mapped registers / CoreSight capabilities?)
  static constexpr uint32_t FP_CTRL_addr = 0xE0002000;
  static volatile uint32_t *FP_CTRL_REG = (uint32_t*)(FP_CTRL_addr);

  static constexpr uint32_t FP_CTRL_FLAG_EN  = 0x1; // LSB enables FPB unit.
  static constexpr uint32_t FP_CTRL_FLAG_KEY = 0x2; // bit must be set for any writes to FP_CTRL.

  // Register describing address remapping capabilities and base address for remap table.
  static constexpr uint32_t FP_REMAP_addr = 0xE0002004;
  static volatile uint32_t *FP_REMAP_REG = (uint32_t*)(FP_REMAP_addr);

  // "magic key" stored in r2 that hints to our DebugMon_Handler that r0 and r1
  // are valid flag num and flag data addr.
  static constexpr uint32_t BKPT_FLAGS_KEY = 0xADB0EEEE;

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

/** Data structure to hold CPU/arch identification bytes to relay to debugger. */
union _dbg_cpu_id {
  uint8_t cpu_bytes[4];
  uint32_t cpu_dword;
};
typedef union _dbg_cpu_id dbg_cpu_id_t;

dbg_cpu_id_t cpu_signature; // runtime-detected fingerprint to identify CPU architecture.
static constexpr uint32_t INVALID_CPU_SIGNATURE = 0xFFFFFFFF;


/** Debugger status bits and typedefs **/
#if defined (__AVR_ARCH__)
  typedef uint8_t dbg_status_t;
  typedef uint16_t dbg_stackptr_t; // Assumes we have SPH & SPL.
#elif defined (ARDUINO_ARCH_SAMD)
  typedef uint32_t dbg_status_t;
  typedef uint32_t dbg_stackptr_t;
#else
  // Fallback case / unknown architecture only uses low-order bits.
  typedef uint8_t dbg_status_t;
  typedef uint16_t dbg_stackptr_t; // Assumes 16 bit stack ptr.
#endif /* Architecture select */
volatile dbg_status_t debug_status = 0;

static inline void _set_dbg_status(dbg_status_t new_status) {
  debug_status = new_status;
  #if defined (ARDUINO_ARCH_SAMD)
    // Ensure synchronization of the debug status to prevent debugger service from
    // interrupting itself.
    __DMB();
  #endif /* ARCH_SAMD */
}

static constexpr dbg_status_t DBG_STATUS_IN_BREAK     = 0x1; // True if we are inside the debugger service.
static constexpr dbg_status_t DBG_STATUS_OP_BKPT      = 0x2; // BKPT opcode triggered dbg service.
static constexpr dbg_status_t DBG_STATUS_DEBUG_MON_EN = 0x4; // Onboard debug monitor enabled (SAMD51).
static constexpr dbg_status_t DBG_STATUS_STEP_BKPT    = 0x8; // True if a single-step triggered debugging.
#if defined (ARDUINO_ARCH_SAMD)
  static constexpr dbg_status_t DBG_STATUS_HW_BKPT    = 0x10000; // Hardware breakpoint register match
  static constexpr dbg_status_t DBG_STATUS_WATCH      = 0x20000; // Watchpoint register match
  static constexpr dbg_status_t DBG_STATUS_STEP2CONT  = 0x40000; // We want to 'continue' after HW BP;
                                                                 // 1st we need to step past bp addr,
                                                                 // then do the continue.
#endif /* ARCH_SAMD */

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
#define DBG_OP_ARCH_SPEC 'a' // Report architecture-dependent specification of capabilities
                             // or parameters to the debugger.
#define DBG_OP_BREAK     'B' // Break execution of the program. (Redundant if within server)
#define DBG_OP_CONTINUE  'C' // Continue execution.
#define DBG_OP_DEBUGCTL  'D' // Architecture-specific debugger extension sentences.
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

#define DBG_END_LIST '$'    // list-based commands end responds with a '$' on a line by itself.

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


/** Helpers for enabling/disabling hardware breakpoint capabilities. */
#if defined(ARDUINO_ARCH_SAMD)
  /** Enable the flashpatch & breakpoint (FPB) unit for hardware breakpoint support. */
  static inline void samd_enable_fpb() {
    uint32_t fp_ctrl_val = *FP_CTRL_REG;
    fp_ctrl_val |= FP_CTRL_FLAG_EN | FP_CTRL_FLAG_KEY;  // Set EN and KEY bits high together.
    *FP_CTRL_REG = fp_ctrl_val; // Write back to FP_CTRL register.
  }

  /** Disable the flashpatch & breakpoint (FPB) unit for hardware breakpoint support. */
  static inline void samd_disable_fpb() {
    uint32_t fp_ctrl_val = *FP_CTRL_REG;
    fp_ctrl_val |= FP_CTRL_FLAG_KEY;  // Set KEY bit high to enable change
    fp_ctrl_val &= ~FP_CTRL_FLAG_EN;  // Set EN flag low.
    *FP_CTRL_REG = fp_ctrl_val; // Write back to FP_CTRL register.
  }
#endif /* ARDUINO_ARCH_SAMD */


/**
 * Setup function for debugger; called before user's setup function.
 * Activate I/O and IRQs required for debugger operation.
 */
void __dbg_setup() {
  DBG_SERIAL.begin(DBG_SERIAL_SPEED);

  noInterrupts();
  #if defined(__AVR_ARCH__)

    // Fill out CPUID signature using signature bytes.
    // See https://microchipsupport.force.com/s/article/How-to-read-signature-byte
    cpu_signature.cpu_bytes[0] = boot_signature_byte_get(0x0);
    cpu_signature.cpu_bytes[1] = boot_signature_byte_get(0x2);
    cpu_signature.cpu_bytes[2] = boot_signature_byte_get(0x4);
    cpu_signature.cpu_bytes[3] = 0x0; // Only 3 sig bytes for AVR. Keep MSB at zero.

    // Set up IRQ on AVR Timer1 (4 Hz)
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

    // Fill out CPUID signature from $CPUID register in the system control block (SCB).
    cpu_signature.cpu_dword = SCB->CPUID;

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

    // All systems go for timer.
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

    // Enable hardware breakpoints.
    samd_enable_fpb();

  #else
    // Mystery architecture! This will surely end well.
    cpu_signature.cpu_dword = INVALID_CPU_SIGNATURE;

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

#ifdef ARDUINO_ARCH_SAMD
  /** Clear bits that are set when entering DebugMon_Handler by various means. */
  static inline void samd_clear_dfsr_and_scb() {
    // Clear Debug Fault Status Register (DFSR) bits in System Control Block (SCB).
    static constexpr uint32_t DFSR_TRAP_BITS =
        SCB_DFSR_HALTED_Msk | SCB_DFSR_BKPT_Msk | SCB_DFSR_DWTTRAP_Msk;
    SCB->DFSR |= DFSR_TRAP_BITS;  // Clear DWTTRAP, BKPT, HALTED bits by writing a '1' to each of them.
    // If we ran a single-step instruction, clear the MON_STEP and MON_PEND bits of DEMCR.
    CoreDebug->DEMCR &= ~(1 << CoreDebug_DEMCR_MON_STEP_Pos);
    CoreDebug->DEMCR &= ~(1 << CoreDebug_DEMCR_MON_PEND_Pos);
  }
#endif /* SAMD */

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
    samd_clear_dfsr_and_scb();
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

    volatile register dbg_stackptr_t SP asm("sp");
    switch(cmd) {
    case DBG_OP_BREAK:
      __dbg_report_pause(bp_num, breakpoint_flags, hw_addr);
      break;
    case DBG_OP_RESET:
      __dbg_reset();
      break;
    case DBG_OP_ARCH_SPEC:
      // Architecture-specific: return flags, register values, etc. that describe the
      // capabilities of the running CPU or its current state. Various other debugger
      // capabilities (e.g., number of hardware breakpoints) may require this run-time
      // parameterization rather than being completely specified by the CPU part id.

      DBG_SERIAL.println(cpu_signature.cpu_dword, HEX); // CPU signature always first in ARCH_SPEC.
      #if defined(__AVR_ARCH__)
        // Nothing to report for AVR.
      #elif defined(ARDUINO_ARCH_SAMD)
        DBG_SERIAL.println(*FP_CTRL_REG, HEX); // FP_CTRL: Describe flashpatch/breakpoint unit.
        DBG_SERIAL.println(*FP_REMAP_REG, HEX); // FP_REMAP: Describe flashpatch remapping capabilities.
        DBG_SERIAL.println(DWT->CTRL, HEX); // DWT_CTRL: Describe data watchpoint & trace unit.
      #endif /* Architecture select */
      // In all cases, this list-driven operation ends with the list-end identifier.
      DBG_SERIAL.println(DBG_END_LIST);
      break;
    case DBG_OP_DEBUGCTL:
      // Control architecture-specific hardware debug/break/watchpoint capabilities.
      // Sentence-structure is architecture-specific.
      // (Placeholder; none currently implemented.)
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
      DBG_SERIAL.println(DBG_END_LIST);
      break;
    case DBG_OP_REGISTERS:
      #if defined(__AVR_ARCH__)

        // 32 general purpose registers are mem-mapped at 0x00..0x1F (mega32u4 ds fig. 4-2)
        for(addr = 0; addr < 32; addr++) {
          DBG_SERIAL.println(*((uint8_t*)addr), HEX);
        }
        // Special registers: SP (AVR note: 16 bit), SREG
        DBG_SERIAL.println(SP, HEX);
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
        DBG_SERIAL.println(__get_CONTROL(), HEX);  // Return $CONTROL register.

      #endif /* architecture select */
      DBG_SERIAL.println(DBG_END_LIST);
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
          // Disable FPB so that if the $PC is sitting on a hardware breakpoint we can proceed.
          samd_disable_fpb();
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
      #ifdef ARDUINO_ARCH_SAMD
        if (debug_status & DBG_STATUS_HW_BKPT) {
          // The $PC is on a hardware breakpoint. If we attempt to continue, we'll insta-break.
          // We need to disable the FPB, take a single step, and use DebugMon_Handler to re-enable
          // FPB for matching $PC against future breakpoints.
          samd_disable_fpb();
          CoreDebug->DEMCR |= 1 << CoreDebug_DEMCR_MON_STEP_Pos; // Set up single-step.
          _set_dbg_status(debug_status | DBG_STATUS_STEP2CONT); // next DebugMon will just continue.
        }
      #endif /* ARCH_SAMD */
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

  #if defined(__AVR_ARCH__)
    __dbg_service(flag_num, flags, 0);
  #elif defined(ARDUINO_ARCH_SAMD)
    if (_hw_bkpt_supported && debug_status & DBG_STATUS_DEBUG_MON_EN) {
      // We have monitor-mode debugging enabled. Use a "real" breakpoint opcode
      // to shift into the debug monitor irq (and from there to the dbg service).
      // This enables us to enter single-step mode cleanly if desired by the user.
      asm volatile (
        "mov r0, %[flag_num]  \n\t" // flag_num and flags_addr identify soft bp; pass to DebugMon_Handler
        "mov r1, %[flags_addr]\n\t" // to forward to dbg_service() via registers r0 & r1.
        "mov r2, %[magic_key] \n\t" // "magic key" tells DebugMon_Handler() that r0 and r1 are valid.
        "bkpt                 \n\t"
        "and r2, r2, #0       \n\t" // Wipe magic key so we don't misinterpret register values if we
                                    // reenter DebugMon_Handler() again soon.
      :
      : [flag_num] "h" (flag_num),
        [flags_addr] "h" (flags),
        [magic_key] "h" (BKPT_FLAGS_KEY)
      : "r0", "r1", "r2"
      );
    } else {
      // Invoke __dbg_service() directly on the thread-mode call stack.
      __dbg_service(flag_num, flags, 0);
    }
  #else
    // default for unknown arch
    __dbg_service(flag_num, flags, 0);
  #endif /* Architecture select */
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

  #if defined(__AVR_ARCH__)
    __dbg_service(flag_num, flags, 0);
  #elif defined(ARDUINO_ARCH_SAMD)
    if (_hw_bkpt_supported && debug_status & DBG_STATUS_DEBUG_MON_EN) {
      // We have monitor-mode debugging enabled. Use a "real" breakpoint opcode
      // to shift into the debug monitor irq (and from there to the dbg service).
      // This enables us to enter single-step mode cleanly if desired by the user.
      asm volatile (
        "mov r0, %[flag_num]  \n\t" // flag_num and flags_addr identify soft bp; pass to DebugMon_Handler
        "mov r1, %[flags_addr]\n\t" // to forward to dbg_service() via registers r0 & r1.
        "mov r2, %[magic_key] \n\t" // "magic key" tells DebugMon_Handler() that r0 and r1 are valid.
        "bkpt                 \n\t"
        "and r2, r2, #0       \n\t" // Wipe magic key so we don't misinterpret register values if we
                                    // reenter DebugMon_Handler() again soon.
      :
      : [flag_num] "h" (flag_num),
        [flags_addr] "h" (flags),
        [magic_key] "h" (BKPT_FLAGS_KEY)
      : "r0", "r1", "r2"
      );
    } else {
      // Invoke __dbg_service() directly on the thread-mode call stack.
      __dbg_service(flag_num, flags, 0);
    }
  #else
    // default for unknown arch
    __dbg_service(flag_num, flags, 0);
  #endif /* Architecture select */
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

  static constexpr uint16_t ARM_BKPT_OP = 0xBE00;  // BKPT is 0xBEnn
  static constexpr uint16_t ARM_BKPT_MASK = 0xFF00; // Only read the high byte. lo-byte is user def'd

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

  extern "C" void DebugMon_Handler(void)
      __attribute__((naked, interrupt, used, no_instrument_function, optimize("no-reorder-blocks")));
  extern "C" void DebugMon_Handler(void) {
    // Handler fired when a debug event occurs (BKPT instruction, or hardware breakpoint/watchpoint)

    // This is a naked ISR. We have implemented our own prologue to eliminate surprises. This
    // method needs to read specific stack data above the current call frame, from the pre-IRQ
    // stacked register data, meaning we need to know the start of our own stack frame in this
    // method; since gcc does not generate a frame pointer, we set up our own. We are
    // conservative about what we push in here to avoid destroying normal-thread state.
    //
    // `no-reorder-blocks` is enforced so that the epilogue (and the manually-constructed CFI
    // records) remain at the absolute end of the method rather than be relocated by compiler
    // optimizations.
    //
    // We may also have soft breakpoint handle details passed in (stacked) registers:
    // r0 -- flag_num
    // r1 -- flags_addr
    // r2 -- magic key (BKPT_FLAGS_KEY) indicating that r0 and r1 are valid
    asm volatile (
        ".cfi_def_cfa sp, 0 \n\t"
        "mov   r12, sp      \n\t" // Save pre-prologue $SP value in r12 for use as a frame pointer.
        ".cfi_undefined 12  \n\t" // r12 is clobbered.
        // Push everything that might be clobbered in this method, or a callee.
        // True $LR is also pre-stacked but we need to save the EXN_RETURN status value it currently
        // holds.
        // We also save all other ABI callee-save registers here.
        "push  {r4, r5, r6, r7, r8, r9, r10, fp, r12, lr} \n\t"
        ".cfi_offset 14, -4 \n\t"   // $LR is reg #14; pushed at $entrySP - 4.
        ".cfi_offset 12, -8 \n\t"   // r12
        ".cfi_offset 11, -12\n\t"   // $FP
        ".cfi_offset 10, -16\n\t"   // r10
        ".cfi_offset 9,  -20\n\t"   // r9
        ".cfi_offset 8,  -24\n\t"   // ...
        ".cfi_offset 7,  -28\n\t"
        ".cfi_offset 6,  -32\n\t"
        ".cfi_offset 5,  -36\n\t"
        ".cfi_offset 4,  -40\n\t"
        ".cfi_adjust_cfa_offset 40\n\t" // We pushed 10x4 = 40 bytes to the stack.
    :
    :
    : "memory"                      // Modifies $SP and RAM. Tell gcc not to optimize this.
    );

    volatile register uint32_t framePtr asm("r12");  // $r12 contains $SP on entry (i.e. it acts
                                                     // as a frame pointer).
                                                     // The old r12 was already stacked on IRQ entry.
                                                     // This points to a CortexM_IRQ_Frame of data.
    uint32_t return_pc = ((CortexM_IRQ_Frame*)(framePtr))->PC;
    uint8_t flag_num = 0;
    uint16_t *flags = NULL;
    uint32_t magic_key = ((CortexM_IRQ_Frame*)(framePtr))->r2;

    // If FPB was disabled (e.g. by 'step') ensure it's enabled again.
    samd_enable_fpb();
    if (debug_status & DBG_STATUS_STEP2CONT) {
      // We did a 'step' to execute an instr w/ a hardware bp sitting on it (with the FPB disabled).
      // Now that we have done that and re-enabled FPB, we should do a full 'continue' without
      // entering the debug service.
      samd_clear_dfsr_and_scb(); // Clear trap info bits.
      _set_dbg_status(debug_status & ~DBG_STATUS_STEP2CONT); // Clear STEP2CONT flag.

      goto debug_mon_epilogue; // Immediate 'return'. Do not enter __dbg_service(). Drop out to epilogue.
    } if (SCB->DFSR & (1 << SCB_DFSR_HALTED_Pos)) {
      // This was triggered by single-stepping.
      _set_dbg_status(debug_status | DBG_STATUS_IN_BREAK | DBG_STATUS_STEP_BKPT);
    } else if (SCB->DFSR & (1 << SCB_DFSR_DWTTRAP_Pos)) {
      // This breakpoint was triggered by the DWT (watchpoint) on a memory addr or on the $PC.
      // If on the $PC, the instruction at the watched $PC has already been executed. Likewise,
      // the instruction performing memory I/O has already performed the read or write access.
      // The DebugReturnAddress (our $LR) points to the next instruction to execute.

      // Record that we are in watchpoint-break status.
      _set_dbg_status(debug_status | DBG_STATUS_IN_BREAK | DBG_STATUS_WATCH);
    } else {
      // We entered this method because of a BKPT instruction (as opposed to after a single-step..)
      // or because of a hardware breakpoint register match in the FPB.
      //
      // On entry to this IRQ, BKPT instructions (or hardware breakpoint comparator
      // matches) will stack the $pc of the BKPT instruction itself rather than the next
      // $PC. Meaning when we exit this handler, we'll resume execution... right on top of
      // the breakpoint (infinite loop back to here).  We need to advance the $PC
      // ourselves. If a hardware bkpt comparator, the instruction has not been executed.

      // `BKPT <n>` has opcode 0xBEnn. If we see see that pattern, advance the $PC over the
      // breakpoint. (If we are not stopped on a BKPT then the FPB fired on the $PC and
      // we don't want to skip the instruction.)
      if (ARM_BKPT_OP == (*((uint16_t*)((CortexM_IRQ_Frame*)(framePtr))->PC) & ARM_BKPT_MASK)) {
        ((CortexM_IRQ_Frame*)(framePtr))->PC += 2;

        if (magic_key == BKPT_FLAGS_KEY) {
          // We hit a software BKPT and it was initialized with flags ptr and flag_num from __dbg_break().
          // These were put in registers that were stacked on IRQ entry; read back here:
          flag_num = (uint8_t)(((CortexM_IRQ_Frame*)(framePtr))->r0);
          flags = (uint16_t *)(((CortexM_IRQ_Frame*)(framePtr))->r1);
          return_pc = 0; // Don't pass literal $PC back to debugger, since it's the addr of the BKPT
                         // within __dbg_break() that isn't unique to this logical breakpoint
                         // location. Let the debugger walk up stack to the caller of __dbg_break().
        }

        // Record that we are in BKPT opcode-break status.
        _set_dbg_status(debug_status | DBG_STATUS_IN_BREAK | DBG_STATUS_OP_BKPT);
      } else {
        // Triggered FPB: Record that we matched a hardware breakpoint as we entered break status.
        _set_dbg_status(debug_status | DBG_STATUS_IN_BREAK | DBG_STATUS_HW_BKPT);
      }
    }

    // Invoke __dbg_service() with the return addr from the triggering breakpoint.
    __dbg_service(flag_num, flags, return_pc);

    // Withdraw from hardware-break status. Create a mask for all flags applied in this method.
    static constexpr dbg_status_t all_flags = DBG_STATUS_IN_BREAK
                                            | DBG_STATUS_OP_BKPT
                                            | DBG_STATUS_STEP_BKPT
                                            | DBG_STATUS_HW_BKPT
                                            | DBG_STATUS_WATCH;
    _set_dbg_status(debug_status & ~all_flags);

debug_mon_epilogue:
    // Hard-coded ISR epilogue.
    asm volatile (
        "ldmia.w sp!, {r4, r5, r6, r7, r8, r9, r10, fp, r12, lr} \n\t"
        ".cfi_register 13, 0        \n\t" // After the POP, the 'real' $SP is in r0.
        ".cfi_restore 14            \n\t" // $LR is restored.
        ".cfi_restore 12            \n\t" // $r12 is restored.
        ".cfi_restore 11            \n\t" // $FP is restored.
        ".cfi_restore 10            \n\t" // r10 is restored, along with other gen-regs...
        ".cfi_restore 9             \n\t"
        ".cfi_restore 8             \n\t"
        ".cfi_restore 7             \n\t"
        ".cfi_restore 6             \n\t"
        ".cfi_restore 5             \n\t"
        ".cfi_restore 4             \n\t"
        ".cfi_adjust_cfa_offset -40 \n\t" // $SP -= 40, is now sitting on its CFA again.
        "mov     sp, r12            \n\t" // $SP fully restored.
        ".cfi_restore 13            \n\t" // $SP is now stored in itself.
        "bx      lr                 \n\t" // Adios! (r0..r3, r12, sp, lr, pc restored in ISR de-stack.)
        "nop                        \n\t"
    :
    :
    : "memory"                      // Full epilogue including return instruction. Force non-opt.
    );
  }
#endif /* architecture select */
