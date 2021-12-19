// (c) Copyright 2021 Aaron Kimball

#include "LCD-NHD0440.h"

NewhavenLcd0440::NewhavenLcd0440() {
  _row = 0;
  _col = 0;
  _byteSender = NULL;

  _displayFlags1 = 0;
  _displayFlags2 = 0;
}

NewhavenLcd0440::~NewhavenLcd0440() {
  _byteSender = NULL; // discard reference to associated object. do not free in here, it was never ours.
}

void NewhavenLcd0440::init(NhdByteSender *byteSender) {
  _byteSender = byteSender;

  // Wait for millis() [time since boot] > HD_0440_BOOT_TIME_MILLIS.
  // The device needs to go thru its internal setup logic before it can accept commands.
  unsigned long start_time = millis();
  while (start_time < NHD_0440_BOOT_TIME_MILLIS) {
    unsigned long remaining = NHD_0440_BOOT_TIME_MILLIS - start_time + 1;
    delay(remaining);
    start_time = millis();
  }

  // Configure the receiver for 4-bit bus mode. If we're only connected to 4 bus lines, we can't
  // send the entire LCD_OP_FUNC_SET command since it'd take two I2C commands. Just send the high
  // nibble to configure the bus mode, then reinitialize.
  // According to the ST7066U datasheet (p.25), we actually start with an 8-bit bus config,
  // repeated 3x to clear any prior 4- or 8-bit bus state, then we downgrade to 4-bit mode.
  uint8_t flags = LCD_RW_WRITE | LCD_RS_COMMAND;

  for (uint8_t i = 0; i < 3; i++) {
    // Send 8-bit-at-once command to affirm 8-bit bus. db3..db0 are 'X' / don't care in this config.
    start_time = micros();
    _byteSender->sendHighNibble(LCD_OP_FUNC_SET | FUNC_SET_8_BIT_BUS, flags, true);
    _byteSender->sendHighNibble(LCD_OP_FUNC_SET | FUNC_SET_8_BIT_BUS, flags, false);
    _waitReady(start_time, NHD_DEFAULT_DELAY_US);
  }

  // Send command to shift to 4-bit-bus mode. We send this as an 8-bit command,
  // so we only send the high nibble.
  start_time = micros();
  _byteSender->sendHighNibble(LCD_OP_FUNC_SET_WITH_DATA_LEN, flags, true);
  _byteSender->sendHighNibble(LCD_OP_FUNC_SET_WITH_DATA_LEN, flags, false);
  _waitReady(start_time, NHD_DEFAULT_DELAY_US);

  // We are now in 4-bit mode. We want to configure other settings, so we transmit
  // both nibbles one after the other: the opcode & 4-bit bus flag, followed by line
  // count & font size.
  start_time = micros();
  _byteSender->sendByte(LCD_OP_FUNC_SET_WITH_DATA_LEN | FUNC_SET_2_LINES | FUNC_SET_FONT_5x8, flags, true);
  _byteSender->sendByte(LCD_OP_FUNC_SET_WITH_DATA_LEN | FUNC_SET_2_LINES | FUNC_SET_FONT_5x8, flags, false);
  _waitReady(start_time, NHD_DEFAULT_DELAY_US);

  // Reset display flags in case they were previously corrupt.
  _displayFlags1 = 0;
  _displayFlags2 = 0;

  // Configure the display into a known, clean state.
  setDisplayVisible(true);
  setCursor(true, true);
  clear();

  // Set ENTRY_MODE to be CURSOR_RIGHT.
  start_time = micros();
  _byteSender->sendByte(LCD_OP_ENTRY_MODE_SET | LCD_ENTRY_MODE_CURSOR_RIGHT, flags, true);
  _byteSender->sendByte(LCD_OP_ENTRY_MODE_SET | LCD_ENTRY_MODE_CURSOR_RIGHT, flags, false);
  _waitReady(start_time, NHD_DEFAULT_DELAY_US);

  // The display is now ready for text.
}

void NewhavenLcd0440::clear() {
  unsigned long start_time = micros();
  uint8_t flags = LCD_RW_WRITE | LCD_RS_COMMAND;
  _byteSender->sendByte(LCD_OP_CLEAR, flags, true);  // E1
  _byteSender->sendByte(LCD_OP_CLEAR, flags, false); // E2

  _waitReady(start_time, NHD_CLEAR_DELAY_US);
  _row = 0;
  _col = 0;
  _setCursorDisplay(DISPLAY_TOP);
}

void NewhavenLcd0440::home() {
  unsigned long start_time = micros();
  uint8_t flags = LCD_RW_WRITE | LCD_RS_COMMAND;
  _byteSender->sendByte(LCD_OP_RETURN_HOME, flags, true);  // E1
  _byteSender->sendByte(LCD_OP_RETURN_HOME, flags, false); // E2

  _waitReady(start_time, NHD_HOME_DELAY_US);
  _row = 0;
  _col = 0;
  _setCursorDisplay(DISPLAY_TOP);
}

void NewhavenLcd0440::setDisplayVisible(bool visible) {
  if (visible) {
    _displayFlags1 |= LCD_DISPLAY_ON;
    _displayFlags2 |= LCD_DISPLAY_ON;
  } else {
    _displayFlags1 &= ~LCD_DISPLAY_ON;
    _displayFlags2 &= ~LCD_DISPLAY_ON;
  }

  _sendDisplayFlags();
}

void NewhavenLcd0440::setCursor(bool visible, bool blinking) {
  // Only manipulate cursor for the active lcd subscreen (based on cursor row).
  // The inactive subscreen should always have no cursor shown.
  uint8_t *flagPtr = (_row < 2) ? &_displayFlags1 : &_displayFlags2;
  if (visible) {
    *flagPtr |= LCD_CURSOR_ON;
  } else {
    *flagPtr &= ~LCD_CURSOR_ON;
  }

  if (blinking) {
    *flagPtr |= LCD_CURSOR_BLINK;
  } else {
    *flagPtr &= ~LCD_CURSOR_BLINK;
  }

  _sendDisplayFlags();
}

// Which of the two subscreens is a given row on?
static uint8_t _subscreenForRow(uint8_t row) {
  return (row < 2) ? DISPLAY_TOP : DISPLAY_BOTTOM;
}

/**
 * Set the cursor position in the 4x40 char screen. In practice this means determining
 * which of the two subscreens we're on, moving the cursor appropriately within the subscreen,
 * and setting cursor visibility only on the appropriate subscreen.
 */
void NewhavenLcd0440::setCursorPos(uint8_t row, uint8_t col) {
  uint8_t subscreen = _subscreenForRow(row);
  bool enablePin = subscreen == DISPLAY_TOP; // Choose e1 or e2 based on subscreen for row.

  uint8_t inScreenRow = (row >= 2) ? (row - 2) : row; // Row within subscreen.
  uint8_t flags = LCD_RW_WRITE | LCD_RS_COMMAND;
  uint8_t addr = col + ((inScreenRow == 0) ? 0 : 0x40);
  unsigned long start_time = micros();
  _byteSender->sendByte(LCD_OP_SET_DDRAM_ADDR | addr, flags, enablePin);
  _waitReady(start_time, NHD_DEFAULT_DELAY_US);

  _setCursorDisplay(subscreen); // Make sure cursor is on the right subscreen.

  _row = row; // Save this as our new position.
  _col = col;
}

// Ensures the cursor is visible on the specified display subscreen.
void NewhavenLcd0440::_setCursorDisplay(uint8_t displayNum) {
  uint8_t curDisplay = _subscreenForRow(_row);
  if (curDisplay == displayNum) {
    return; // Nothing to do.
  }

  // Swap the active display.
  uint8_t tmp = _displayFlags1;
  _displayFlags1 = _displayFlags2;
  _displayFlags2 = tmp;

  _sendDisplayFlags();
}

// Send display and cursor vis flags to device.
void NewhavenLcd0440::_sendDisplayFlags() {
  unsigned long start_time = micros();
  uint8_t flags = LCD_RW_WRITE | LCD_RS_COMMAND;
  _byteSender->sendByte(LCD_OP_DISPLAY_ON_OFF | _displayFlags1, flags, true);  // E1
  _byteSender->sendByte(LCD_OP_DISPLAY_ON_OFF | _displayFlags2, flags, false); // E2
  _waitReady(start_time, NHD_DEFAULT_DELAY_US);
}

/**
 * Wait until the display is ready / finished processing the command.
 */
void NewhavenLcd0440::_waitReady(unsigned long start_time, unsigned int delay_micros) {
  unsigned long now = micros();
  if (now < start_time) {
    // Handle microsecond clock rollover.
    start_time = now;
  }
  unsigned long elapsed = now - start_time;

  while (elapsed < delay_micros) {
    // TODO(aaron): Actually read the busy-flag field and wait for it to drop to zero
    delayMicroseconds(delay_micros - elapsed);
    now = micros();
    if (now < start_time) {
      start_time = now;
    }
    elapsed = now - start_time;
  }
}

// Actually write a byte to the screen.
size_t NewhavenLcd0440::write(uint8_t chr) {
  if (chr == '\r') {
    _col = 0;
    setCursorPos(_row, _col);
    return 1;
  } else if (chr == '\n') {
    _col = 0;
    uint8_t newRow = _row + 1;
    if (newRow >= LCD_NUM_ROWS) {
      newRow = 0; // Wrap back to the top.
      // TODO(aaron): Make it scroll up!
    }
    setCursorPos(newRow, _col); // _row updated in setCursorPos().
    return 1;
  }

  uint8_t flags = LCD_RW_WRITE | LCD_RS_DATA;
  // choose enable flag based on current row.
  bool enableFlag = _subscreenForRow(_row) == DISPLAY_TOP;
  unsigned long start_time = micros();
  _byteSender->sendByte(chr, flags, enableFlag);
  _waitReady(start_time, NHD_DEFAULT_DELAY_US);
  _col++;
  if (_col >= LCD_NUM_COLS) {
    // Move to the next line.
    _col = 0;
    uint8_t newRow = _row + 1;
    if (newRow >= LCD_NUM_ROWS) {
      newRow = 0; // Wrap back to the top.
      // TODO(aaron): Make it scroll up!
    }
    setCursorPos(newRow, _col); // _row updated in setCursorPos().
  }

  return 1;
}


