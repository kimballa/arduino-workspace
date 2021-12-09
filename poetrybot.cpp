#include<Arduino.h>

// pin definitions.
const int R = 6;
const int G = 5;

const int TIC = 100; // blink interval

void setup() {
  // put your setup code here, to run once:
  pinMode(R, OUTPUT);
  pinMode(G, OUTPUT);

  digitalWrite(R, 0);
  digitalWrite(G, 0);  
}

void loop() {
  // put your main code here, to run repeatedly:
  digitalWrite(R, 1);
  delay(TIC);
  digitalWrite(G, 1);
  delay(TIC);
  digitalWrite(R, 0);
  delay(TIC);
  digitalWrite(G, 0);
  delay(TIC);


}
