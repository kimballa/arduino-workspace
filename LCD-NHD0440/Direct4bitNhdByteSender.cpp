// (c) Copyright 2021 Aaron Kimball

#include "LCD-NHD0440.h"
#include "nanodelay.h"

Direct4bitNhdByteSender::Direct4bitNhdByteSender(
    uint8_t EN1, uint8_t EN2, uint8_t RW, uint8_t RS,
    uint8_t DB7, uint8_t DB6, uint8_t DB5, uint8_t DB4):
    _EN1(EN1), _EN2(EN2), _RW(RW), _RS(RS), _DB7(DB7), _DB6(DB6), _DB5(DB5), _DB4(DB4) {
}

Direct4bitNhdByteSender::~Direct4bitNhdByteSender() {
}

void Direct4bitNhdByteSender::init() {
  pinMode(_RW, OUTPUT);
  pinMode(_RS, OUTPUT);
  pinMode(_DB7, OUTPUT);
  pinMode(_DB6, OUTPUT);
  pinMode(_DB5, OUTPUT);
  pinMode(_DB4, OUTPUT);
  pinMode(_EN1, OUTPUT);
  pinMode(_EN2, OUTPUT);

  // While initializing the NHD0440 wants all its inputs pulled low.
  digitalWrite(_RW, LOW);
  digitalWrite(_RS, LOW);
  digitalWrite(_DB7, LOW);
  digitalWrite(_DB6, LOW);
  digitalWrite(_DB5, LOW);
  digitalWrite(_DB4, LOW);
  digitalWrite(_EN1, LOW);
  digitalWrite(_EN2, LOW);
}

// We need to wait 80ns (T_DSW) after last DB port write for data setup time, but more
// importantly need to wait a full 485ns (T_R + T_PW) after pulling up EN before we can
// trigger EN via falling edge.
#define DIRECT_PORT_SETUP_TIME_NS (485)

/* Set one or both enable lines to state (HIGH or LOW) based on enFlags. */
void Direct4bitNhdByteSender::_setEnable(uint8_t state, uint8_t enFlags) {
  if (enFlags & LCD_E1) { digitalWrite(_EN1, state); }
  if (enFlags & LCD_E2) { digitalWrite(_EN2, state); }
}

void Direct4bitNhdByteSender::sendByte(uint8_t v, uint8_t ctrlFlags, uint8_t enFlags) {
  // Set enable to HIGH to setup for falling edge when ready.
  _setEnable(HIGH, enFlags);

  // Flags stay consistent through entire send operation.
  digitalWrite(_RW, ctrlFlags & LCD_RW);
  digitalWrite(_RS, ctrlFlags & LCD_RS);

  // Send high nibble first.
  digitalWrite(_DB7, v & 0x80);
  digitalWrite(_DB6, v & 0x40);
  digitalWrite(_DB5, v & 0x20);
  digitalWrite(_DB4, v & 0x10);
  HALF_MICRO_WAIT(); // Wait for worst-case pin setup time (485ns, rounded up to 500)
  _setEnable(LOW, enFlags); // lock in high nibble

  // falling-edge time (T_F) and data hold time (T_H) are only 10+25 = 35ns, but
  // the complete cycle time before we can raise EN back to HIGH is 1200ns. A fair bit of this was
  // consumed by the digitalWrite() operations but wait a full 500ns here just to be sure.
  HALF_MICRO_WAIT();

  // Send low nibble.
  _setEnable(HIGH, enFlags); // Set enable to HIGH to setup for falling edge when ready.
  digitalWrite(_DB7, v & 0x8);
  digitalWrite(_DB6, v & 0x4);
  digitalWrite(_DB5, v & 0x2);
  digitalWrite(_DB4, v & 0x1);
  HALF_MICRO_WAIT(); // Wait for worst-case pin setup time
  _setEnable(LOW, enFlags); // lock in low nibble
  _NOP(); // Wait for final T_F + T_H

}

void Direct4bitNhdByteSender::sendHighNibble(uint8_t v, uint8_t ctrlFlags, uint8_t enFlags) {
  // Set enable to HIGH to setup for falling edge when ready.
  _setEnable(HIGH, enFlags);

  // Flags stay consistent through entire send operation.
  digitalWrite(_RW, ctrlFlags & LCD_RW);
  digitalWrite(_RS, ctrlFlags & LCD_RS);

  // Send high nibble of 'v'..
  digitalWrite(_DB7, v & 0x80);
  digitalWrite(_DB6, v & 0x40);
  digitalWrite(_DB5, v & 0x20);
  digitalWrite(_DB4, v & 0x10);
  HALF_MICRO_WAIT(); // Wait for worst-case pin setup time (485ns, rounded up to 500)
  _setEnable(LOW, enFlags); // lock in high nibble.

  // falling-edge time (T_F) and data hold time (T_H) are only 10+25 = 35ns, but
  // the complete cycle time before we can raise EN back to HIGH is 1200ns. 
  // Block here to ensure a complete cycle is realized.
  HALF_MICRO_WAIT();
}

