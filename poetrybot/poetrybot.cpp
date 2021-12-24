#include<Arduino.h>
#include<Wire.h>

#include <I2CParallel.h>
#include <LCD-NHD0440.h>

#define DEBUG
// #define DBG_WAIT_FOR_CONNECT
// #define DBG_START_PAUSED
#define DBG_PRETTY_FUNCTIONS
#include <dbg.h>

// pin definitions.
static const int R = 6;
static const int G = 5;

static const int TIC = 500; // blink interval

static const int PARALLEL_ADDR = I2C_PCF8574A_MIN_ADDR;

static const uint8_t num_lines = 10;
static const char L0[] PROGMEM = "1, This is the first line";
static const char L1[] PROGMEM = "2, Here is line two";
static const char L2[] PROGMEM = "3, We are on the third line";
static const char L3[] PROGMEM = "4- Here comes the fourth!";
static const char L4[] PROGMEM = "5- We are scrolling decisively";
static const char L5[] PROGMEM = "6- Madly dashing along.";
static const char L6[] PROGMEM = "7th line ends with a newline\n";
static const char L7[] PROGMEM = "8: eighth line";
static const char L8[] PROGMEM = "9: xABCDEF another A third 10,1234567890wrapping around";
static const char L9[] PROGMEM = "A: TEN!!!!";

static const char *const lines[] PROGMEM = {
  L0, L1, L2, L3, L4, L5, L6, L7, L8, L9
};

// buffer to hold elements of `lines` for printing.
static char linebuf[80];

I2C4BitNhdByteSender nhdByteSender;
NewhavenLcd0440 lcd;

SETUP() {
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
  TRACE("trace message");
  DBGPRINT("meep");

  lcd.init(&nhdByteSender);
  lcd.setScrollingTTY(true);
  BREAK();

  //lcd.print(F("GREMBLOR <3 RIANA!\nThis unique device exists just to say\n...You're very special. <3\nXOXOXO Merry Christmas XOXOXO"));
}

static int blinkState = 0;
static int line = 0;
static bool first = true;

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

  //lcd.print("meep\n");
  /*
  int n = 0;
  for (int i = 0; i < 60; i++) {
    lcd.print(n, HEX);
    n++;
    if (n >= 10) {
      n = 0;
    }
    delay(100);
  }
  */
  /*
  line = 8;
  strcpy_P(linebuf, (char*)pgm_read_word(&(lines[line])));
  lcd.print(linebuf);
  */
  //while(true) { delay(50); };

  if (!first) {
    lcd.print("\n");
  }
  strcpy_P(linebuf, (char*)pgm_read_word(&(lines[line])));
  lcd.print(linebuf);
  first = false;
  line++;
  if (line >= num_lines) {
    line = 0;
  }

}
