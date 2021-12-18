// (c) Copyright 2021 Aaron Kimball
//
// Library to use the PCF8574 / PCF8574A
// Remote 8-Bit I/O Expander for I2C Bus
// See datasheet: https://www.ti.com/lit/ds/symlink/pcf8574a.pdf
//
// This depends on the <Wire> library for I2C communication.
// This library is lightweight: just 4 bytes of memory and < 100 bytes of code.
//
// This library does not implement the interrupt logic of the PCF8574.

#ifndef I2C_PARALLEL_H
#define I2C_PARALLEL_H

#include<inttypes.h>
#include<Wire.h>

// The two chips are identical, except for their configurable address ranges:
// PCF8574  address bits: 0 1 0 0 A2 A1 A0 0
// PCF8574A address bits: 0 1 1 1 A2 A1 A0 0

// The PCF8574 uses addresses 0x20 .. 0x27
#define I2C_PCF8574_MIN_ADDR ((uint8_t)0x20)
#define I2C_PCF8574_MAX_ADDR ((uint8_t)0x27)

// The PCF8574A uses addresses 0x38 .. 0x3F
#define I2C_PCF8574A_MIN_ADDR ((uint8_t)0x38)
#define I2C_PCF8574A_MAX_ADDR ((uint8_t)0x3F)

// Use only the 7 less-significant bits of the address.
// This will be left-shifted by 1 and a r/w flag bit appended as the lsb
// for actual communication.
#define I2C_PARALLEL_ADDR_MASK ((uint8_t)0x7F)

// The bus expander operates at a maximum rate of 100 KHz 
#define I2C_PARALLEL_MAX_BUS_SPEED ((uint32_t)100000)

// Timeout duration for I2C communications in microseconds; use 25 ms.
#define I2C_PARALLEL_WIRE_TIMEOUT ((uint32_t)25000)

#define I2C_PARALLEL_MAX_VAL ((uint8_t)0xFF)

// All bus lines begin at logic high.
#define I2C_PARALLEL_DEFAULT_BUS_STATE I2C_PARALLEL_MAX_VAL

// The time delay from I2C acknowledge until the output is valid.
// (Also the hold time needed for driven inputs before the data can be reported back.)
#define I2C_PARALLEL_HOLD_TIME_MICROS ((unsigned int)4)

class I2CParallel {
public:
  I2CParallel();
  ~I2CParallel() {};

  // Configure the 8-bit parallel bus with its expected 7-bit I2C address.
  // This must be within one of the two supported MIN_ADDR .. MAX_ADDR ranges.
  void init(const uint8_t i2cAddr);

  // Set the value to emit on the 8-bit bus. This value is latched and held
  // until overwritten by another setByte() or driven by the other side of the bus.
  void setByte(const uint8_t val);
  void write(const uint8_t val); // synonym for setByte().

  // Read back the current contents of the 8-bit bus. The bus can be driven by
  // connected logic on any lines that we have set to HIGH via setByte(). 
  // On power-up, all data lines initialize to high (getByte() == 0xFF).
  uint8_t getByte();
  uint8_t read(); // synonym for getByte().

  // Read back the last known contents of the bus without actually reading over i2c. 
  uint8_t getLastState() const;

  // Configure some data lines as inputs according to the specified mask.  The
  // masked data lines will be allowed to pull up to logic HIGH and can then be
  // driven by the connected device(s). Subsequently writing a logic LOW to any
  // bits with setByte() will drive those lines low and disable input mode.
  void enableInputs(const uint8_t mask);

  // Apply a bitwise operation to the current bus state.
  void setOr(const uint8_t val);
  void setAnd(const uint8_t val);
  void setXor(const uint8_t val);

  // Increment the bus arithmetically by 1; 0xFF + 1 rolls back to 0.
  void increment();

  // Delay until the transmitted data is ready on the parallel bus,
  // or delay until parallel bus inputs can be queried.
  void waitForValid();

private:
  uint8_t _i2cAddr; // Address of chip on the I2C bus.
  uint8_t _state; // State of the 8 data lines.
};



#endif /* I2C_PARALLEL_H */

