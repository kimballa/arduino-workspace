# (c) Copyright 2021 Aaron Kimball
#
# Arduino-based build and upload capabilities.
#
# You must set the following variables before including this .mk file:
#   BOARD - the fqbn of the board to use (e.g. 'arduino:avr:uno')
#   TARGET - the name of the program to compile

help:
	@echo "Available targets:"
	@echo "===================================="
	@echo "clean         : Remove intermediate / output files"
	@echo "config        : Show configuration"

# Set target dirs
build_dir ?= build

# Set variables for programs we need access to.

# arduino-cli tool
ARDUINO_CLI := $(realpath $(shell which arduino-cli))

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

ifndef TARGET
$(error "The TARGET variable must specify the target program name to compile")
else
	.DEFAULT_GOAL := $(TARGET)
endif

# Specific Arduino variant within fqbn.
VARIANT := $(strip $(shell echo $(BOARD) | head -1 | cut -d ':' -f 3))

# Based on the current $BOARD, look up complete toolchain information from 
# output of `arduino-cli board details`; set the command to call here:
__DETAILS := $(ARDUINO_CLI) board details -b $(BOARD)

# What we are searching for is values to assign to the following variables, which may be overridden
# in advance:
# ARDUINO_PACKAGE - should be 'arduino', 'adafruit', etc; subdir of packages/
# ARCH - should be 'avr', 'samd', etc.
# ARCH_VER - version number for the arch (core file, etc.)
# AVR_CXX - the fully-resolved path to the cross-compiler.
ifeq ($(origin ARDUINO_PACKAGE), undefined)
	ARDUINO_PACKAGE := $(strip $(shell $(__DETAILS) | grep "Package name:" | head -1 | cut -d ':' -f 2))
endif

ifeq ($(origin ARCH), undefined)
	ARCH := $(strip $(shell $(__DETAILS) | grep "Platform architecture:" | head -1 | cut -d ':' -f 2))
endif
ifeq ($(origin ARCH_VER), undefined)
  ARCH_VER := $(strip $(shell $(__DETAILS) | grep "Board version:" | head -1 | cut -d ':' -f 2))
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

arch_upper := $(strip $(shell echo $(ARCH) | tr [:lower:] [:upper:]))

# Board definitions file for this hardware set.
boards_txt := "$(ARDUINO_DATA_DIR)/packages/$(ARDUINO_PACKAGE)/hardware/$(ARCH)/$(ARCH_VER)/boards.txt"

# Compiler flags we need
CXXFLAGS += -fno-exceptions
CXXFLAGS += -ffunction-sections
CXXFLAGS += -fdata-sections
CXXFLAGS += -fno-threadsafe-statics
CXXFLAGS += -x c++
CXXFLAGS += -I$(ARDUINO_DATA_DIR)/packages/$(ARDUINO_PACKAGE)/hardware/$(ARCH)/$(ARCH_VER)/cores/arduino
CXXFLAGS += -I$(ARDUINO_DATA_DIR)/packages/$(ARDUINO_PACKAGE)/hardware/$(ARCH)/$(ARCH_VER)/variants/$(VARIANT)
CXXFLAGS += -flto # link-time optimization
CXXFLAGS += -DARCH_$(arch_upper)

build_mcu := $(strip $(shell grep -e "^$(VARIANT).build.mcu" $(boards_txt) | cut -d '=' -f 2))
CXXFLAGS += -mmcu=$(build_mcu)

build_board_def := $(strip $(shell grep -e "^$(VARIANT).build.board" $(boards_txt) | cut -d '=' -f 2))
CXXFLAGS += -DARDUINO_$(build_board_def) # e.g. -DARDUINO_AVR_LEONARDO

build_f_cpu := $(strip $(shell grep -e "^$(VARIANT).build.f_cpu" $(boards_txt) | cut -d '=' -f 2))
CXXFLAGS += -DF_CPU=$(build_f_cpu)

build_vid := $(strip $(shell grep -e "^$(VARIANT).build.vid" $(boards_txt) | cut -d '=' -f 2))
CXXFLAGS += -DUSB_VID=$(build_vid)

build_pid := $(strip $(shell grep -e "^$(VARIANT).build.pid" $(boards_txt) | cut -d '=' -f 2))
CXXFLAGS += -DUSB_PID=$(build_pid)

build_usb_product := $(strip $(shell grep -e "^$(VARIANT).build.usb_product" $(boards_txt) | cut -d '=' -f 2))
CXXFLAGS += '-DUSB_PRODUCT=$(build_usb_product)'

# TODO(aaron): Questionable to enforce by default... do we want to? (arduino-ide does...)
CXXFLAGS += -Wno-error=narrowing

# Compiler flags we (might) want from arduino-ide's option set.
CXXFLAGS += -Os # optimize for size.
CXXFLAGS += -std=gnu++11
CXXFLAGS += -g  # Debug


config:
	@echo "Ardiuno build configuration:"
	@echo "===================================="
	@echo "Target board  : $(BOARD)"
	@echo "Package       : $(ARDUINO_PACKAGE)"
	@echo "Architecture  : $(ARCH)"
	@echo "Arch version  : $(ARCH_VER)"
	@echo "Variant       : $(VARIANT)"
	@echo "Toolchain ver : $(COMPILER_VERSION)"
	@echo "Toolchain     : $(COMPILER_BINDIR)"
	@echo "Compiler      : $(COMPILER_NAME)"
	@echo ""
	@echo "Tool paths:"
	@echo "===================================="
	@echo "arduino-cli   : $(ARDUINO_CLI)"
	@echo "CXX           : $(CXX)"
	@echo ""
	@echo "Options:"
	@echo "===================================="
	@echo 'CXXFLAGS      : $(CXXFLAGS)'

clean:
	find . -name "*.o" -delete
	-rm -r "$(build_dir)"

core_dir := $(ARDUINO_DATA_DIR)/packages/$(ARDUINO_PACKAGE)/hardware/$(ARCH)/$(ARCH_VER)/cores/arduino
# The cpp files in build/core/ need to be copied into that dir by `core_setup`, so their names can't
# be used as wildcard in depends; rely on the names of the upstream cpp files in the package
# core_dir.
core_cpp_filenames = $(notdir $(wildcard $(core_dir)/*.cpp))
$(build_dir)/core.a : core_setup $(patsubst %.cpp,%.o,$(addprefix $(build_dir)/core/,$(core_cpp_filenames)))
	@echo "TODO core.a rule goes here"

# Copy core cpp files to build dir (don't overwrite existing; don't force it to be out of date)
core_setup:
	mkdir -p "$(build_dir)/core/"
	cp -n "$(core_dir)/"*.cpp "$(build_dir)/core/"


%.o : %.cpp
	$(CXX) -c $(CXXFLAGS) $(CPPFLAGS) $< -o $@


.PHONY: config help clean core_setup
