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
// Note that this can set _pos to illegal values where col >= LCD_NUM_COLS.
// The caller is responsible for detecting overflow.
static inline uint8_t _incrementCol(uint8_t &pos) {
  // col is in low-order bits, so just increment.
  return _getCol(++pos);
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
  _sendCommand(LCD_OP_CLEAR, LCD_EN_ALL, NHD_CLEAR_DELAY_US);
  setCursorPos(0, 0); // Reset Arduino knowledge of cursor & reset active display to TOP.
}

void NewhavenLcd0440::home() {
  _sendCommand(LCD_OP_RETURN_HOME, LCD_EN_ALL, NHD_HOME_DELAY_US);
  setCursorPos(0, 0); // Reset Arduino knowledge of cursor & reset active display to TOP.
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
 * Set the cursor position in the 4x40 char screen.
 *
 * In practice this means determining which of the two subscreens we're on, moving the
 * cursor appropriately within the subscreen, and setting cursor visibility only on the
 * appropriate subscreen.
 */
void NewhavenLcd0440::setCursorPos(uint8_t row, uint8_t col) {
  _setCursorPos(row, col, true);
}

/**
 * Set the cursor position in the 4x40 char screen.
 *
 * If `updateDisplayFlags`, determine which of the two subscreens we're on, move the
 * cursor appropriately within the subscreen, and set cursor visibility only on the
 * appropriate subscreen. Setting to 'false' will skip display flag updates but may
 * cause the display to go out of sync unless you move it back to the right subscreen.
 */
void NewhavenLcd0440::_setCursorPos(uint8_t row, uint8_t col, bool updateDisplayFlags) {
  const uint8_t subscreen = _subscreenForRow(row);
  // Choose e1 or e2 based on subscreen for row.
  const uint8_t enablePin = (subscreen == DISPLAY_TOP) ? LCD_E1 : LCD_E2;

  const uint8_t inScreenRow = (row >= 2) ? (row - 2) : row; // Row within subscreen.
  const uint8_t addr = col + ((inScreenRow == 0) ? 0 : 0x40);
  _sendCommand(LCD_OP_SET_DDRAM_ADDR | addr, enablePin, NHD_DEFAULT_DELAY_US);

  if (updateDisplayFlags) {
    _setCursorDisplay(subscreen); // Make sure cursor is on the right subscreen.
  }
  _pos = _makePos(row, col); // Save this as our new position.
}

// Ensures the cursor is visible on the specified display subscreen.
void NewhavenLcd0440::_setCursorDisplay(uint8_t displayNum) {
  const uint8_t curDisplay = _subscreenForRow(_getRow(_pos));
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
  uint8_t display1 = LCD_OP_DISPLAY_ON_OFF | ((_displayFlags >> DISPLAY_1_SHIFT) & DISPLAY_BITS_MASK);
  uint8_t display2 = LCD_OP_DISPLAY_ON_OFF | ((_displayFlags >> DISPLAY_2_SHIFT) & DISPLAY_BITS_MASK);
  _sendCommand(display1, LCD_E1, 0); // No delay; the 2nd delay handles both subscreens.
  _sendCommand(display2, LCD_E2, NHD_DEFAULT_DELAY_US);
}

void NewhavenLcd0440::setScrollingTTY(bool scroll) {
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
    const uint8_t newRow = _getRow(_pos) + 1;
    if (newRow >= LCD_NUM_ROWS) {
      if (_displayFlags & DISP_FLAG_SCROLL) {
        _scrollScreen();
      } else {
        setCursorPos(0, 0);  // Wrap back to the top.
      }
    } else {
      setCursorPos(newRow, 0); // Move to the next line.
    }
    return 1;
  }

  if (_getCol(_pos) >= LCD_NUM_COLS) {
    // Prior write was to the last column on the screen, and we didn't handle
    // a '\n' or '\r' above, meaning we're writing to the "41st" column. (nope!)
    // Wrap to the next line before printing.
    const uint8_t nextRow = _getRow(_pos) + 1;
    if (nextRow >= LCD_NUM_ROWS) {
      if (_displayFlags & DISP_FLAG_SCROLL) {
        _scrollScreen();
      } else {
        setCursorPos(0, 0); // Wrap back to the top.
      }
    } else {
      setCursorPos(nextRow, 0);
    }
  }

  // We're now in a valid location to write a character.
  static const uint8_t ctrlFlags = LCD_RW_WRITE | LCD_RS_DATA;
  // choose enable flag based on current row.
  const uint8_t enablePin = (_subscreenForRow(_getRow(_pos)) == DISPLAY_TOP) ? LCD_E1 : LCD_E2;
  _byteSender->sendByte(chr, ctrlFlags, enablePin);
  _waitReady(NHD_DEFAULT_DELAY_US);
  _incrementCol(_pos);

  return 1;
}

/**
 * Scroll all the lines up by 1.
 */
void NewhavenLcd0440::_scrollScreen() {

  unsigned long lpr_s, lpr_e;
  t_loop_pos_resets = 0;
  t_lineread = 0;
  t_linewrite = 0;
  unsigned long start = micros();
  static const uint8_t ctrlFlagsR = LCD_RW_READ | LCD_RS_DATA;
  static const uint8_t ctrlFlagsW = LCD_RW_WRITE | LCD_RS_DATA;

  for (uint8_t r = 1; r < LCD_NUM_ROWS; r++) {
    const uint8_t enFlagR = (_subscreenForRow(r) == DISPLAY_TOP) ? LCD_E1 : LCD_E2;
    const uint8_t enFlagW = (_subscreenForRow(r - 1) == DISPLAY_TOP) ? LCD_E1 : LCD_E2;

    // Buffer one row of char RAM locally.
    // NOTE(aaron): This read-all-then-write-all pattern makes use of the LCD's internal
    // cursor to minimize the number of setPosition() calls. If a 40 byte buffer is too
    // big for the stack, we could do this in blocks of 8 chars to compromise between
    // stack usage and I/O latency.
    uint8_t buffer[LCD_NUM_COLS];

    lpr_s = micros();
    _setCursorPos(r, 0, false);
    _byteSender->setBusMode(NHD_MODE_READ);
    lpr_e = micros();
    t_loop_pos_resets += (lpr_e - lpr_s);
    unsigned long rd_s = micros();
    for (uint8_t c = 0; c < LCD_NUM_COLS; c++) {
      // Read operation also moves the cursor 1 to the right.
      buffer[c] = _byteSender->readByte(ctrlFlagsR, enFlagR);
      _waitReady(NHD_DEFAULT_DELAY_US);
    }
    unsigned long rd_e = micros();
    t_lineread += (rd_e - rd_s);

    _byteSender->setBusMode(NHD_MODE_WRITE);
    if (r == LCD_NUM_ROWS - 1) {
      // We just read the last row of the screen, to copy it to the
      // second-to-last row. Clear the bottom display first, to wipe
      // the last line out 0.5ms faster than we could set it byte-by-byte.
      _sendCommand(LCD_OP_CLEAR, LCD_E2, NHD_CLEAR_DELAY_US);
      unsigned long clr_e = micros();
      t_clear = clr_e - rd_e;
    } else {
      // Reset cursor position to prior row.
      _setCursorPos(r - 1, 0, false);
      lpr_e = micros();
      t_loop_pos_resets += (lpr_e - rd_e);
    }

    // Emit the buffer onto the previous line.
    unsigned long wr_s = micros();
    for (uint8_t c = 0; c < LCD_NUM_COLS; c++) {
      _byteSender->sendByte(buffer[c], ctrlFlagsW, enFlagW);
      _waitReady(NHD_DEFAULT_DELAY_US);
    }
    unsigned long wr_e = micros();
    t_linewrite += (wr_e - wr_s);
  }

  unsigned long fpr_s = micros();
  _setCursorPos(LCD_NUM_ROWS - 1, 0, false); // Return cursor to beginning of bottom line.
  unsigned long fpr_e = micros();
  t_final_pos_reset = fpr_e - fpr_s;
  t_scroll = fpr_e - start;
}


void NewhavenLcd0440::_sendCommand(uint8_t cmd, uint8_t enFlags, unsigned int delay_micros) {
  static const uint8_t ctrlFlags = LCD_RW_WRITE | LCD_RS_COMMAND;
  _byteSender->sendByte(cmd, ctrlFlags, enFlags);
  if (delay_micros > 0) {
    _waitReady(delay_micros);
  }
}
