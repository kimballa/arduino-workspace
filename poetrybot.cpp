#include<Arduino.h>
#include<Wire.h>

#include "i2cparallel/I2CParallel.h"
#include "LCD-NHD0440/LCD-NHD0440.h"

// pin definitions.
static const int R = 6;
static const int G = 5;

static const int TIC = 500; // blink interval

static const int PARALLEL_ADDR = I2C_PCF8574A_MIN_ADDR;


I2C4BitNhdByteSender nhdByteSender;
NewhavenLcd0440 lcd;

void setup() {
  // Initialize hardware serial.
//  Serial.begin(115200);
#ifdef __AVR_ATmega32U4__ // Arduino AVR Leonardo
//  while (!Serial) {
//    delay(1); // wait for serial port to connect (Leonardo only).
//  }
#endif

  Wire.begin(); // Open I2C interface
  nhdByteSender.init(PARALLEL_ADDR);


  // Initialize blinkenlights outputs.
  pinMode(R, OUTPUT);
  pinMode(G, OUTPUT);

  digitalWrite(R, 0);
  digitalWrite(G, 0);  

  lcd.init(&nhdByteSender);
  lcd.print("Hello, world!");
}

static int blinkState = 0;

void loop() {
  delay(TIC);

  switch (blinkState) {
  case 0:
    digitalWrite(R, 1);
    break;
  case 1:
    digitalWrite(G, 1);
    break;
  case 2:
    digitalWrite(R, 0);
    break;
  case 3:
    digitalWrite(G, 0);
    break;
  }
  blinkState++;
  if (blinkState > 3) {
    blinkState = 0;
  }

}
