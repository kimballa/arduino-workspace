// (c) Copyright 2021 Aaron Kimball

#include "LCD-NHD0440.h"

I2C4BitNhdByteSender::I2C4BitNhdByteSender(): _i2cp(I2CParallel()) {
}

I2C4BitNhdByteSender::~I2C4BitNhdByteSender() {
}

void I2C4BitNhdByteSender::init(const uint8_t i2cAddr) {
  // Connect to the I2C interface.
  _i2cp.init(i2cAddr); 

  // The PCF8574 starts with all bits high (tri-stated and pulled up)
  // and the LCD wants all bits suppressed on startup; get them low ASAP.
  _i2cp.setByte(0);
}

void I2C4BitNhdByteSender::sendByte(uint8_t v, uint8_t flags, bool useE1) {
  uint8_t out = 0;

  uint8_t enFlag = useE1 ? 0x80 : 0x40; // Set the correct enable flag high.
  const uint8_t enFlag_L_mask = 0x3F;   // Mask with enable flags held low.

  out |= enFlag;
  out |= (flags & LCD_USER_FLAGS);
  // Send the high nibble first.
  out |= (v >> 4) & 0x0F;
    
  _i2cp.setByte(out);
  _i2cp.waitForValid(); // establish EN as HIGH and wait for setup time on data.

  // Drop the enable flag to low to lock the high nibble in.
  out &= enFlag_L_mask;
  _i2cp.setByte(out);
  _i2cp.waitForValid(); // wait for hold time on data after falling edge of EN.

  out = 0;
  out |= enFlag; // Set enable flag high & send low nibble.
  out |= (flags & LCD_USER_FLAGS);
  out |= (v & 0xF); // use low nibble
    
  _i2cp.setByte(out);
  _i2cp.waitForValid();

  // Drop the enable flag to low to lock the second nibble in.
  out &= enFlag_L_mask;
  _i2cp.setByte(out);
  _i2cp.waitForValid();
}

void I2C4BitNhdByteSender::sendHighNibble(uint8_t v, uint8_t flags, bool useE1) {
  uint8_t out = 0;

  uint8_t enFlag = useE1 ? 0x80 : 0x40; // Set the correct enable flag high.
  const uint8_t enFlag_L_mask = 0x3F;   // Mask with enable flags held low.

  out |= enFlag;
  out |= (flags & LCD_USER_FLAGS);
  // Send the high nibble.
  out |= (v >> 4) & 0x0F;
    
  _i2cp.setByte(out);
  _i2cp.waitForValid();

  // Drop the enable flag to low to lock the high nibble in.
  out &= enFlag_L_mask;
  _i2cp.setByte(out);
  _i2cp.waitForValid();
}

