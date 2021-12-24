// (C) Copyright 2021 Aaron Kimball

#include "dbg.h"
#include <Stream.h>

#ifndef FPSTR
#define FPSTR(pstr_pointer) (reinterpret_cast<const __FlashStringHelper *>(pstr_pointer))
#endif /* FPSTR */

// Debugger status bits.
volatile uint8_t debug_status = 0;

#define DBG_STATUS_IN_BREAK  (0x1)  // True if we are inside the debugger service.


// The debugger client sends sentences beginning with a DBG_OP_ and ending with DBG_END.
#define DBG_END          '\n' // end of debugger sentence.

#define DBG_OP_RESET     'R' // Reset CPU.
#define DBG_OP_CALLSTACK 's' // Return call stack info
#define DBG_OP_RAMADDR   '@' // Return data at RAM address
#define DBG_OP_STACKREL  '$' // Return data at addr relative to SP.
#define DBG_OP_FLASHADDR 'f' // Return data at Flash address.
#define DBG_OP_POKE      'K' // Insert data to RAM address.
#define DBG_OP_MEMSTATS  'm' // Describe memory usage
#define DBG_OP_REGISTERS 'r' // Dump registers
#define DBG_OP_PORT_IN   'p' // read gpio pin
#define DBG_OP_PORT_OUT  'P' // write gpio pin
#define DBG_OP_CONTINUE  'C' // continue execution
#define DBG_OP_NONE      DBG_END

#define DBG_RET_PRINT    ('>') // prefix for logged messages that debugger client
                               // should output verbatim to console.


/**
 * Setup function for debugger; called before user's setup function.
 * Activate I/O and IRQs required for debugger operation.
 */
void __dbg_setup() {
  Serial.begin(9600);

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

/**
 * Called at breakpoint in user code (or via ISR if serial traffic arrives). Starts a service
 * that communicates over Serial about the state of the CPU until released to continue by
 * the client.
 */
void __dbg_service() {
  debug_status |= DBG_STATUS_IN_BREAK; // Mark the service as started so we don't recursively re-enter.
  // In order to communicate over UART or USB Serial, we need to keep servicing interrupts within
  // debugger, even if called via IRQ.
  sei();
  // TODO(aaron): Give user a way to disable interrupts of theirs via callback SPI before sei?

  static uint8_t cmd;

  Serial.print(DBG_RET_PRINT);
  Serial.println(F("Paused."));

  while (true) {
    while (!Serial.available()) {
      delay(1);
    }

    cmd = Serial.read();
    if (cmd == DBG_OP_NONE) {
      continue; // Empty input line.
    }

    // Interpret client request sentence.
    unsigned int addr = 0;
    switch(cmd) {
    case DBG_OP_RESET:
      break;
    case DBG_OP_CALLSTACK:
      break;
    case DBG_OP_RAMADDR:
      addr = Serial.parseInt(LookaheadMode::SKIP_WHITESPACE);
      Serial.println(*((uint8_t*)addr), DEC);
      break;
    case DBG_OP_STACKREL:
      break;
    case DBG_OP_FLASHADDR:
      break;
    case DBG_OP_POKE:
      break;
    case DBG_OP_MEMSTATS:
      break;
    case DBG_OP_REGISTERS:
      break;
    case DBG_OP_PORT_IN:
      break;
    case DBG_OP_PORT_OUT:
      break;
    case DBG_OP_CONTINUE: // Continue main program execution; exit debugger.
      if (Serial.available() && Serial.peek() == DBG_END) {
        Serial.read(); // consume expected EOL marker.
      }
      Serial.print(DBG_RET_PRINT);
      Serial.println(F("Continuing..."));
      goto exit_loop;
      break;
    default: // Unknown command.
      break;
    }

    if (Serial.available() && Serial.peek() == DBG_END) {
      Serial.read(); // consume expected EOL marker.
    }
  }
exit_loop:

  debug_status &= ~DBG_STATUS_IN_BREAK; // Mark debug service as closed.
}


bool __dbg_assert(bool test, const String &assertStr, const String &funcOrFile,
    const unsigned int lineno) {

  if (test) {
    return test; // Assert succeeded.
  }

  Serial.print(DBG_RET_PRINT);
  Serial.print(F("Assertion failure ("));
  Serial.print(funcOrFile);
  Serial.print('(');
  Serial.print(lineno, DEC);
  Serial.print(')');
  Serial.print(':');
  Serial.print(' ');
  Serial.println(assertStr);

  return false;
}


void __dbg_trace(const String &tracemsg, const String &funcOrFile, const uint16_t lineno) {
  Serial.print(DBG_RET_PRINT);
  Serial.print(funcOrFile);
  Serial.print('(');
  Serial.print(lineno, DEC);
  Serial.print(')');
  Serial.print(':');
  Serial.print(' ');
  Serial.println(tracemsg);
}

void __dbg_print(const char *message) {
  Serial.print(DBG_RET_PRINT);
  Serial.println(message);
}

void __dbg_print(const String &message) {
  Serial.print(DBG_RET_PRINT);
  Serial.println(message);
}

void __dbg_print(bool msg) {
  Serial.print(DBG_RET_PRINT);
  if (msg) {
    Serial.println(F("true"));
  } else {
    Serial.println(F("false"));
  }
}

void __dbg_print(uint8_t msg) {
  Serial.print(DBG_RET_PRINT);
  Serial.println(msg, DEC);
}

void __dbg_print(int msg) {
  Serial.print(DBG_RET_PRINT);
  Serial.println(msg, DEC);
}

void __dbg_print(long msg) {
  Serial.print(DBG_RET_PRINT);
  Serial.println(msg, DEC);
}

void __dbg_print(unsigned int msg) {
  Serial.print(DBG_RET_PRINT);
  Serial.println(msg, DEC);
}

void __dbg_print(unsigned long msg) {
  Serial.print(DBG_RET_PRINT);
  Serial.println(msg, DEC);
}

static const char _breakpoint_msg[] PROGMEM = "Breakpoint at ";

void __dbg_break(const char *funcOrFile, const uint16_t lineno) {
  Serial.print(DBG_RET_PRINT);
  Serial.print(FPSTR(_breakpoint_msg));
  Serial.print(funcOrFile);
  Serial.print(':');
  Serial.print(' ');
  Serial.println(lineno, DEC);

  __dbg_service();
}

void __dbg_break(const String &funcOrFile, const uint16_t lineno) {
  Serial.print(DBG_RET_PRINT);
  Serial.print(FPSTR(_breakpoint_msg));
  Serial.print(funcOrFile);
  Serial.print(':');
  Serial.print(' ');
  Serial.println(lineno, DEC);

  __dbg_service();
}


/**
 * 1Hz timer fires for us to check whether data is available on Serial port.
 * If we have a request from the debugger client, we break into the debugger service.
 */
ISR(TIMER1_COMPA_vect) {
  if (!(debug_status & DBG_STATUS_IN_BREAK) && Serial.available()) {
    // Enter debug service if serial traffic available, and we are not already within the dbg
    // service.
    __dbg_service();
  }
}
