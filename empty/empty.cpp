// (c) Copyright 2021 Aaron Kimball
//
// A very simple pin-blinking program with a "minimal program size"
// to use as a benchmark for how much overhead libraries add.
//
// This makes use of *some* functionality from Arduino.h that is very common
// so we don't unfairly charge the library for making modest use of the Arduino core;
// it would otherwise virtually all be stripped out.
#include<Arduino.h>

#define DEBUG
#define DBG_PRETTY_FUNCTIONS
#include <dbg.h>

static const int PIN = 5;

void SETUP() {
  pinMode(PIN, OUTPUT);
}

static uint8_t state = 0;

void loop() {
  state = !state;
  digitalWrite(PIN, state);
  delay(500);
}

