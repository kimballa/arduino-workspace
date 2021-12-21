// (C) Copyright 2021 Aaron Kimball
//
// Driver for Newhaven Devices 0440-series 4x40 char LCDs
// These LCDs are integrated on top of a pair of ST7066U LCD ICs.
// (A Hitachi HD44780-compatible chip.)
//
// Datasheet references:
// * Display:   https://www.mouser.com/datasheet/2/291/NHD-0440WH-ATFH-JT-47935.pdf
// * Driver IC: https://www.newhavendisplay.com/resources_dataFiles/datasheets/LCDs/ST7066U.pdf
//
// This driver uses the 4-bit bus mode (not 8-bit).
//
// This can either be directly attached to 8 I/O lines of the AVR, or the E1,
// E2, RW, RS, and the 4 data bits can be collectively attached over an I2C
// 8-bit bus connected with the I2CParallel lib.  In this mode, the LCD can be
// controlled with only 2 shared I2C pins from the AVR.
//
// You must instantiate the correct NhdByteSender based on the connection mode:
//
//    /* -- Use one of the following two code snippets -- */
//    // Connect via I2C to PCF8574[A] parallel port.
//    Wire.begin();
//    I2C4BitNhdByteSender byteSender();
//    byteSender.init(I2C_PCF8574A_MIN_ADDR); // or your addr of parallel port on I2C bus.
//
//    /* --or-- */
//    // Use Arduino D11..D4 gpio pins as direct-wired bus.
//    Direct4BitNhdByteSender byteSender(11, 10, 9, 8, 7, 6, 5, 4);
//    byteSender.init();
//
//    /* -- Then follow either of the above with -- */
//    NewhavenLcd0440 lcd;
//    lcd.init(&byteSender); // Connect LCD to bus & send LCD init commands.
//
//    /* -- Then use LCD according to API. e.g.: -- */
//    lcd.print("Hello, world!");
//    delay(1000);
//    lcd.clear(); // clear screen
//    lcd.setCursor(2, 0); // put cursor on 3rd row
//    lcd.print("More text...");
//
//

#ifndef LCD_NHD_0440_H
#define LCD_NHD_0440_H

#include<Arduino.h>
#include<I2CParallel.h>

class NhdByteSender {
public:
  NhdByteSender() {};
  ~NhdByteSender() {};

  // Must be overridden by implementation class
  virtual void sendByte(uint8_t v, uint8_t ctrlFlags, uint8_t enFlags) = 0;
  /* Send the high nibble of v with RW/RS and latch. */
  virtual void sendHighNibble(uint8_t v, uint8_t ctrlFlags, uint8_t enFlags) = 0;
  /* Read a byte from the NHD memory. */
  virtual uint8_t readByte(uint8_t ctrlFlags, uint8_t enFlag) = 0;
  /** Switch between NHD_MODE_WRITE and NHD_MODE_READ. */
  virtual void setBusMode(uint8_t busMode) = 0;
};

#define NHD_MODE_WRITE (OUTPUT)
#define NHD_MODE_READ  (INPUT)

/**
 * Send data to the NHD 0440 in 4-bit bus mode. The Arduino sends data over I2C
 * to a PCF8574 8-bit bus expander (via I2CParallel lib). The 8-bit bus i/o is wired
 * to the NHD 0440 as follows:
 * P7 P6 P5 P4  P3  P2  P1  P0 <-- PCF8574
 * E1 E2 RW RS DB7 DB6 DB5 DB4 <-- LCD0440
 */
class I2C4BitNhdByteSender : public NhdByteSender {
public:
  I2C4BitNhdByteSender();
  ~I2C4BitNhdByteSender();

  // Initialize the I2C interface. Due to the fact that the PCF8574 initially
  // starts with all bits high (actually tri-stated, but pullups draw them high),
  // you should call this method as early as possible in the boot process.
  void init(const uint8_t i2cAddr);

  /* Send the byte value 'v'; initialize RW/RS via ctrlFlags; latch with E1 and/or E2
   * based on enFlags.
   */
  virtual void sendByte(uint8_t v, uint8_t ctrlFlags, uint8_t enFlags);
  /* Send the high nibble of v with RW/RS and latch. */
  virtual void sendHighNibble(uint8_t v, uint8_t ctrlFlags, uint8_t enFlags);
  /* Read a byte from the NHD memory. */
  virtual uint8_t readByte(uint8_t ctrlFlags, uint8_t enFlag);
  /** Switch between NHD_MODE_WRITE and NHD_MODE_READ. */
  virtual void setBusMode(uint8_t busMode);
private:
  I2CParallel _i2cp;
};

/**
 * Send data to the NHD 0440 in 4-bit bus mode. The Arduino sends data using
 * 8 GPIO pins wired to the NHD 0440.
 *
 * The LCD0440 has 8 I/O pins as follows: En1 En2 RW RS DB7 DB6 DB5 DB4.
 * You must initialize the ByteSender with Arduino pin numbers that map to each
 * of these. (In 4-bit mode, DB3..0 are not used and should be tied to GND.)
 */
class Direct4BitNhdByteSender : public NhdByteSender {
public:
  Direct4BitNhdByteSender(uint8_t EN1, uint8_t EN2, uint8_t RW, uint8_t RS,
      uint8_t DB7, uint8_t DB6, uint8_t DB5, uint8_t DB4);
  ~Direct4BitNhdByteSender();

  void init(); // Set up the GPIO pins as outputs and pull them low.

  /* Send the byte value 'v'; initialize RW/RS via ctrlFlags; latch with E1 and/or E2
   * based on enFlags.
   */
  virtual void sendByte(uint8_t v, uint8_t ctrlFlags, uint8_t enFlags);
  /* Send the high nibble of v with RW/RS and latch. */
  virtual void sendHighNibble(uint8_t v, uint8_t ctrlFlags, uint8_t enFlags);
  /* Read a byte from the NHD memory. */
  virtual uint8_t readByte(uint8_t ctrlFlags, uint8_t enFlag);
  /** Switch between NHD_MODE_WRITE and NHD_MODE_READ. */
  virtual void setBusMode(uint8_t busMode);
private:
  void _setEnable(uint8_t state, uint8_t enFlags);
  const uint8_t _EN1, _EN2, _RW, _RS, _DB7, _DB6, _DB5, _DB4;
};


// Main API to control the Newhaven 0440 series LCD
class NewhavenLcd0440 : public Print {
public:
  NewhavenLcd0440();
  ~NewhavenLcd0440();

  void init(NhdByteSender *byteSender);  // setup lcd board state.
  void clear(); // clear screen and return home
  void home();  // return cursor to home position
  void setDisplayVisible(bool visible);        // turn display on or off
  void setCursor(bool visible, bool blinking); // turn cursor on or off
  void reset() { init(_byteSender); }; // reset LCD state.

  // Set position on row 0--3, col 0--39 across the two subscreens.
  void setCursorPos(uint8_t row, uint8_t col);

  void setScrolling(bool scroll); // Enable/disable scrolling display.

  virtual size_t write(uint8_t chr); // write 1 character thru the Print interface.

private:
  void _sendCommand(uint8_t cmd, uint8_t enFlags, unsigned int delay_micros);
  void _setCursorDisplay(uint8_t displayNum);
  void _sendDisplayFlags();
  void _waitReady(unsigned int delay_micros);
  void _scrollScreen(); 

  NhdByteSender* _byteSender;

  uint8_t _pos; // row is [0--3] in ROW_MASK, col is [0--39] in COL_MASK.
  uint8_t _displayFlags; // state of display flags for both subscreens.
};

#define COL_MASK  ((uint8_t)0x3F)
#define COL_SHIFT ((uint8_t)0)

#define ROW_MASK  ((uint8_t)0xC0)
#define ROW_SHIFT ((uint8_t)6)


#define DISP_FLAG_D1 ((uint8_t)0x4) // display visible (subscreen 1)
#define DISP_FLAG_C1 ((uint8_t)0x2) // cursor vis
#define DISP_FLAG_B1 ((uint8_t)0x1) // blink

#define DISP_FLAG_D2 ((uint8_t)0x20) // display visible (subscreen 2)
#define DISP_FLAG_C2 ((uint8_t)0x10) // cursor vis
#define DISP_FLAG_B2 ((uint8_t)0x08) // blink

#define DISP_FLAG_SCROLL ((uint8_t)0x40) // flag to indicate scrolling behavior after 4th line

#define DISPLAY_BITS_MASK ((uint8_t)0x7)
#define DISPLAY_1_SHIFT ((uint8_t)0)
#define DISPLAY_2_SHIFT ((uint8_t)3)


#define LCD0440_BUS_WIDTH 4 // 4-bit interface mode.

// Bitmasks for 'flags' fields when transmitted with a nibble of user data
// over a combined 8 bit bus.
#define LCD_E1 0x80
#define LCD_E2 0x40
#define LCD_RW 0x20
#define LCD_RS 0x10

// Caller of NhdByteSender::sendByte() controls RW and RS through `flags`.
// The ByteSender manages E1 and E2 internally via `useE1` argument.
#define LCD_CTRL_FLAGS (LCD_RS | LCD_RW)
#define LCD_ENABLE_FLAGS (LCD_E1 | LCD_E2)

// Bitfield pattern for all (both) enable lines.
#define LCD_EN_ALL (LCD_E1 | LCD_E2)

// LCD_RW signal values
#define LCD_RW_READ    (LCD_RW)
#define LCD_RW_WRITE   (0)

// LCD_RS signal values.
#define LCD_RS_COMMAND (0)
#define LCD_RS_DATA    (LCD_RS)

// Bit flags for LCD control operations
#define LCD_OP_CLEAR          0x1
#define LCD_OP_RETURN_HOME    0x2
#define LCD_OP_ENTRY_MODE_SET 0x4
#define LCD_OP_DISPLAY_ON_OFF 0x8
#define LCD_OP_DISPLAY_SHIFT  0x10
#define LCD_OP_FUNC_SET       0x20
#define LCD_OP_SET_CGRAM_ADDR 0x40
#define LCD_OP_SET_DDRAM_ADDR 0x80

// Possible combinations of LCD_OP_ENTRY_MODE_SET and flags defining 4 behaviors
#define LCD_ENTRY_MODE_CURSOR_RIGHT (LCD_OP_ENTRY_MODE_SET | 0x2)
#define LCD_ENTRY_MODE_CURSOR_LEFT  (LCD_OP_ENTRY_MODE_SET)
#define LCD_ENTRY_MODE_SHIFT_RIGHT  (LCD_OP_ENTRY_MODE_SET | 0x1)
#define LCD_ENTRY_MODE_SHIFT_LEFT   (LCD_OP_ENTRY_MODE_SET | 0x1 | 0x2)

// Flags to combine with LCD_OP_DISPLAY_ON_OFF
#define LCD_DISPLAY_ON   0x4
#define LCD_CURSOR_ON    0x2
#define LCD_CURSOR_BLINK 0x1

// Possible combination of LCD_OP_DISPLAY_SHIFT and flags defining 4 actions to take:
#define LCD_DISPLAY_SHIFT_CURSOR_LEFT   (LCD_OP_DISPLAY_SHIFT)
#define LCD_DISPLAY_SHIFT_CURSOR_RIGHT  (LCD_OP_DISPLAY_SHIFT | 0x4)
#define LCD_DISPLAY_SHIFT_DISPLAY_LEFT  (LCD_OP_DISPLAY_SHIFT | 0x8)
#define LCD_DISPLAY_SHIFT_DISPLAY_RIGHT (LCD_OP_DISPLAY_SHIFT | 0x8 | 0x4)

// Define the FUNCTION_SET operation flag along with the `DL` field set for
// the correct bus width
#if LCD0440_BUS_WIDTH == 4
#define LCD_OP_FUNC_SET_WITH_DATA_LEN (LCD_OP_FUNC_SET | FUNC_SET_4_BIT_BUS)
#elif LCD0440_BUS_WIDTH == 8
#define LCD_OP_FUNC_SET_WITH_DATA_LEN (LCD_OP_FUNC_SET | FUNC_SET_8_BIT_BUS)
#else
#error "LCD0440_BUS_WIDTH is not defined. Should be 4 or 8."
#endif

// Flags to combine with LCD_OP_FUNC_SET_WITH_DATA_LEN.
// Note that 2_LINES and FONT_5x11 are incompatible; setting 2_LINES forces 5x8 font.
#define FUNC_SET_8_BIT_BUS 0x10
#define FUNC_SET_4_BIT_BUS 0
#define FUNC_SET_2_LINES   0x8
#define FUNC_SET_1_LINE    0x0
#define FUNC_SET_FONT_5x8  0x0
#define FUNC_SET_FONT_5x11 0x4

// Address masks to use with LCD_OP_SET_CGRAM_ADDR and _SET_DDRAM_ADDR
#define CGRAM_ADDR_MASK 0x3F
#define DDRAM_ADDR_MASK 0x7F

// Cannot operate the NHD0440 until millis() returns > BOOT_TIME_MILLIS
// (tIOL is min 40ms; we need to hold the IO pins *low* during this period.)
#define NHD_0440_BOOT_TIME_MILLIS ((unsigned long)50)

// Delay timing in microseconds for NHD0440 operations after communicating over the bus
// to the ST7066.

// Delay timing for 'clear' and 'home' commands
#define NHD_CLEAR_DELAY_US          1520
#define NHD_HOME_DELAY_US           1520
// Delay timing for all other commands, RAM reads and writes
#define NHD_DEFAULT_DELAY_US          37
// Despite only 37us needed for most commands, the busy flag isn't valid until T+80us
#define NHD_BUSY_FLAG_POLL_DELAY_US   80

// Fastest we can push data thru the bus and cycle the enable flag to high, low, and high again.
// If using the I2C bus this is irrelevant since each state change has a 4us hold time, but
// a direct pinout connection could violate this timing constraint unless guarded against.
#define NHD_BUS_CYCLE_TIME_NS       1200

// internal id numbers for the two sub-screens. enable-line E1 latches the top
// subscreen (rows 0 & 1), E2 latches for the bottom subscreen (rows 2 & 3).
#define DISPLAY_TOP    ((uint8_t)0)
#define DISPLAY_BOTTOM ((uint8_t)1)

#define LCD_NUM_ROWS  ((uint8_t)4)
#define LCD_NUM_COLS  ((uint8_t)40)

#endif /* LCD_NHD_0440_H */
