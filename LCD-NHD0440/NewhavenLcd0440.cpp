// (c) Copyright 2021 Aaron Kimball

#include "LCD-NHD0440.h"

// Return row portion of _pos.
static inline uint8_t _getRow(uint8_t pos) {
  return (pos & ROW_MASK) >> ROW_SHIFT;
}

// Return column portion of _pos.
static inline uint8_t _getCol(uint8_t pos) {
  return (pos & COL_MASK) >> COL_SHIFT;
}

// Create a _pos field from a row and column.
static inline uint8_t _makePos(uint8_t row, uint8_t col) {
  return ((row << ROW_SHIFT) & ROW_MASK) | ((col << COL_SHIFT) & COL_MASK);
}

// Increment the 'col' field of pos by 1 and return the new 'col' value.
static inline uint8_t _incrementCol(uint8_t &pos) {
  uint8_t row = _getRow(pos);
  uint8_t col = _getCol(pos) + 1;
  pos = _makePos(row, col + 1); // set thru reference.
  return col;
}

NewhavenLcd0440::NewhavenLcd0440() {
  _pos = 0;
  _byteSender = NULL;
  _displayFlags = 0;
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
  const uint8_t ctrlFlags = LCD_RW_WRITE | LCD_RS_COMMAND;

  for (uint8_t i = 0; i < 3; i++) {
    // Send 8-bit-at-once command to affirm 8-bit bus. db3..db0 are 'X' / don't care in this config.
    _byteSender->sendHighNibble(LCD_OP_FUNC_SET | FUNC_SET_8_BIT_BUS, ctrlFlags, LCD_EN_ALL);
    _waitReady(NHD_DEFAULT_DELAY_US);
  }

  // Send command to shift to 4-bit-bus mode. We send this as an 8-bit command,
  // so we only send the high nibble.
  _byteSender->sendHighNibble(LCD_OP_FUNC_SET_WITH_DATA_LEN, ctrlFlags, LCD_EN_ALL);
  _waitReady(NHD_DEFAULT_DELAY_US);

  // We are now in 4-bit mode. We want to configure other settings, so we transmit
  // both nibbles one after the other: the opcode & 4-bit bus flag, followed by line
  // count & font size.
  _byteSender->sendByte(LCD_OP_FUNC_SET_WITH_DATA_LEN | FUNC_SET_2_LINES | FUNC_SET_FONT_5x8,
      ctrlFlags, LCD_EN_ALL);
  _waitReady(NHD_DEFAULT_DELAY_US);

  // Reset display flags in case they were previously corrupt.
  _displayFlags = 0;

  // Configure the display into a known, clean state.
  setDisplayVisible(true);
  setCursor(true, true);
  clear();

  // Set ENTRY_MODE to be CURSOR_RIGHT.
  _byteSender->sendByte(LCD_OP_ENTRY_MODE_SET | LCD_ENTRY_MODE_CURSOR_RIGHT, ctrlFlags, LCD_EN_ALL);
  _waitReady(NHD_DEFAULT_DELAY_US);

  // The display is now ready for text.
}

void NewhavenLcd0440::clear() {
  const uint8_t ctrlFlags = LCD_RW_WRITE | LCD_RS_COMMAND;
  _byteSender->sendByte(LCD_OP_CLEAR, ctrlFlags, LCD_EN_ALL);
  _waitReady(NHD_CLEAR_DELAY_US);

  setCursorPos(0, 0);
}

void NewhavenLcd0440::home() {
  const uint8_t ctrlFlags = LCD_RW_WRITE | LCD_RS_COMMAND;
  _byteSender->sendByte(LCD_OP_RETURN_HOME, ctrlFlags, LCD_EN_ALL);
  _waitReady(NHD_HOME_DELAY_US);

  setCursorPos(0, 0);
}

void NewhavenLcd0440::setDisplayVisible(bool visible) {
  if (visible) {
    _displayFlags |= DISP_FLAG_D1 | DISP_FLAG_D2;
  } else {
    _displayFlags &= (~DISP_FLAG_D1) & (~DISP_FLAG_D2);
  }

  _sendDisplayFlags();
}

void NewhavenLcd0440::setCursor(bool visible, bool blinking) {
  // Only manipulate cursor for the active lcd subscreen (based on cursor row).
  // The inactive subscreen should always have no cursor shown.
  uint8_t vis_mask, blink_mask;
  if (_getRow(_pos) < 2) {
    vis_mask = DISP_FLAG_C1;
    blink_mask = DISP_FLAG_B1;
  } else {
    vis_mask = DISP_FLAG_C2;
    blink_mask = DISP_FLAG_B2;
  }

  if (visible) {
    _displayFlags |= vis_mask;
  } else {
    _displayFlags &= ~vis_mask;
  }

  if (blinking) {
    _displayFlags |= blink_mask;
  } else {
    _displayFlags &= ~blink_mask;
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
  // Choose e1 or e2 based on subscreen for row.
  uint8_t enablePin = (subscreen == DISPLAY_TOP) ? LCD_E1 : LCD_E2;

  uint8_t inScreenRow = (row >= 2) ? (row - 2) : row; // Row within subscreen.
  const uint8_t ctrlFlags = LCD_RW_WRITE | LCD_RS_COMMAND;
  uint8_t addr = col + ((inScreenRow == 0) ? 0 : 0x40);
  _byteSender->sendByte(LCD_OP_SET_DDRAM_ADDR | addr, ctrlFlags, enablePin);
  _waitReady(NHD_DEFAULT_DELAY_US);

  _setCursorDisplay(subscreen); // Make sure cursor is on the right subscreen.
  _pos = _makePos(row, col); // Save this as our new position.
}

// Ensures the cursor is visible on the specified display subscreen.
void NewhavenLcd0440::_setCursorDisplay(uint8_t displayNum) {
  uint8_t curDisplay = _subscreenForRow(_getRow(_pos));
  if (curDisplay == displayNum) {
    return; // Nothing to do.
  }

  // Swap the active display.
  uint8_t d1 = (_displayFlags >> DISPLAY_1_SHIFT) & DISPLAY_BITS_MASK;
  uint8_t d2 = (_displayFlags >> DISPLAY_2_SHIFT) & DISPLAY_BITS_MASK;
  _displayFlags = (d1 << DISPLAY_2_SHIFT) | (d2 << DISPLAY_1_SHIFT) | (_displayFlags & DISP_FLAG_SCROLL);

  _sendDisplayFlags();
}

// Send display and cursor vis flags to device.
void NewhavenLcd0440::_sendDisplayFlags() {
  const uint8_t ctrlFlags = LCD_RW_WRITE | LCD_RS_COMMAND;
  uint8_t display1 = LCD_OP_DISPLAY_ON_OFF | ((_displayFlags >> DISPLAY_1_SHIFT) & DISPLAY_BITS_MASK);
  uint8_t display2 = LCD_OP_DISPLAY_ON_OFF | ((_displayFlags >> DISPLAY_2_SHIFT) & DISPLAY_BITS_MASK);
  _byteSender->sendByte(display1, ctrlFlags, LCD_E1);
  _byteSender->sendByte(display2, ctrlFlags, LCD_E2);
  _waitReady(NHD_DEFAULT_DELAY_US);
}

void NewhavenLcd0440::setScrolling(bool scroll) {
  if (scroll) {
    _displayFlags |= DISP_FLAG_SCROLL;
  } else {
    _displayFlags &= ~DISP_FLAG_SCROLL;
  }
}

/**
 * Wait until the display is ready / finished processing the command.
 */
void NewhavenLcd0440::_waitReady(unsigned int delay_micros) {
  unsigned long start_time = micros();
  unsigned long elapsed = 0;

  while (elapsed < delay_micros) {
    // TODO(aaron): Actually read the busy-flag field and wait for it to drop to zero
    delayMicroseconds(delay_micros - elapsed);
    unsigned long now = micros();
    if (now < start_time) {
      start_time = now;
    }
    elapsed = now - start_time;
  }
}

// Actually write a byte to the screen.
size_t NewhavenLcd0440::write(uint8_t chr) {
  if (chr == '\r') {
    setCursorPos(_getRow(_pos), 0);
    return 1;
  } else if (chr == '\n') {
    uint8_t newRow = _getRow(_pos) + 1;
    if (newRow >= LCD_NUM_ROWS) {
      newRow = 0; // Wrap back to the top.
      // TODO(aaron): Make it scroll up!
    }
    setCursorPos(newRow, 0); 
    return 1;
  }

  const uint8_t ctrlFlags = LCD_RW_WRITE | LCD_RS_DATA;
  // choose enable flag based on current row.
  uint8_t enablePin = (_subscreenForRow(_getRow(_pos)) == DISPLAY_TOP) ? LCD_E1 : LCD_E2;
  _byteSender->sendByte(chr, ctrlFlags, enablePin);
  _waitReady(NHD_DEFAULT_DELAY_US);

  if (_incrementCol(_pos) >= LCD_NUM_COLS) {
    // Move to the next line.
    uint8_t newRow = _getRow(_pos) + 1;
    if (newRow >= LCD_NUM_ROWS) {
      newRow = 0; // Wrap back to the top.
      // TODO(aaron): Make it scroll up!
    }
    setCursorPos(newRow, 0); 
  }

  return 1;
}


