# (c) Copyright 2021 Aaron Kimball
#
# Arduino-based build and upload capabilities.
#
#
#

# Set variables for programs we need access to.

# arduino-cli tool
ARDUINO_CLI := arduino-cli

# Set conventions
SHELL ?= /bin/bash
.SUFFIXES:
.SUFFIXES: .ino .cpp .cxx .C .o


# ARDUINO_DATA_DIR: Where does arduino-cli store its toolchain packages?
__data_dir_1 = $(strip $(shell $(ARDUINO_CLI) config dump | grep 'data' | head -1 | cut -d ':' -f 2))
ifndef ARDUINO_DATA_DIR
	ARDUINO_DATA_DIR := $(strip $(__data_dir_1))
endif

ifndef BOARD
$(error "The BOARD variable must specify the active board fqbn. e.g.: 'arduino:avr:uno'")
endif

# Based on the current $BOARD, look up complete toolchain information from 
# output of `arduino-cli board details`; set the command to call here:
__DETAILS := $(ARDUINO_CLI) board details -b $(BOARD)

# What we are searching for is values to assign to the following variables, which may be overridden
# in advance:
# ARDUINO_PACKAGE - should be 'arduino', 'adafruit', etc; subdir of packages/
# ARDUINO_ARCH - should be 'avr', 'samd', etc.
# AVR_CXX - the fully-resolved path to the cross-compiler.
ifeq ($(origin ARDUINO_PACKAGE), undefined)
	ARDUINO_PACKAGE := $(strip $(shell $(__DETAILS) | grep "Package name:" | head -1 | cut -d ':' -f 2))
endif
ifeq ($(origin ARDUINO_ARCH), undefined)
	ARDUINO_ARCH := $(strip $(shell $(__DETAILS) | grep "Platform architecture:" | head -1 | cut -d ':' -f 2))
endif
ifeq ($(origin AVR_CXX), undefined)
	__COMPILER_TOOLS := $(strip $(shell $(__DETAILS) | grep "Required tool" | grep "gcc" | head -1 ))
	COMPILER_TOOLS_DIR := $(strip $(shell echo "$(__COMPILER_TOOLS)" | cut -d ' ' -f 3 | cut -d ':' -f 2))
	COMPILER_VERSION := $(strip $(shell echo "$(__COMPILER_TOOLS)" | cut -d ' ' -f 4))
	COMPILER_BINDIR := $(ARDUINO_DATA_DIR)/packages/$(ARDUINO_PACKAGE)/tools/$(COMPILER_TOOLS_DIR)/$(COMPILER_VERSION)/bin
	COMPILER_NAME := $(strip $(shell ls -1 $(COMPILER_BINDIR) | grep 'g++' | head -1))

	# We have found the fully-qualified path to the g++ to use.
	AVR_CXX := $(realpath $(COMPILER_BINDIR)/$(COMPILER_NAME))
endif
CXX := $(AVR_CXX)

config:
	@echo "Data dir is [$(ARDUINO_DATA_DIR)]"
	@echo "Package is [$(ARDUINO_PACKAGE)]"
	@echo "Arch is [$(ARDUINO_ARCH)]"
	@echo "Tools raw is [$(__COMPILER_TOOLS)]"
	@echo "Tools dir is [$(COMPILER_TOOLS_DIR)]"
	@echo "Tools ver is [$(COMPILER_VERSION)]"
	@echo "bindir [$(COMPILER_BINDIR)]"
	@echo "name [$(COMPILER_NAME)]"
	@echo "CXX: [$(CXX)]"

