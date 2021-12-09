# (c) Copyright 2021 Aaron Kimball
#
# Arduino-based build and upload capabilities.
#
# You must set the following variables before including this .mk file:
#   BOARD - the fqbn of the board to use (e.g. 'arduino:avr:uno')
#   TARGET - the name of the program to compile

ARDUINO_MK_VER = "1.0.0"

.DEFAULT_GOAL := image

help:
	@echo "Available targets:"
	@echo "===================================="
	@echo "clean         : Remove intermediate / output files"
	@echo "config        : Show configuration"
	@echo "core          : Build the Arduino core"
	@echo "image         : (default) Compile code and prepare upload-ready files"
	@echo ""
	@echo "$(TARGET)     : Compile your code"


# Set target dirs
build_dir ?= build

# Specify all directories containing .cpp files to compile.
src_dirs ?= .



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
$(error "The `BOARD` variable must specify the active board fqbn. e.g.: 'arduino:avr:uno'")
endif

ifndef prog_name
$(error "The `prog_name` variable must specify the target program name to compile")
endif

ifndef TARGET
TARGET = $(build_dir)/$(prog_name).elf
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


__COMPILER_TOOLS := $(strip $(shell $(__DETAILS) | grep "Required tool" | grep "gcc" | head -1 ))
COMPILER_TOOLS_DIR := $(strip $(shell echo "$(__COMPILER_TOOLS)" | cut -d ' ' -f 3 | cut -d ':' -f 2))
COMPILER_VERSION := $(strip $(shell echo "$(__COMPILER_TOOLS)" | cut -d ' ' -f 4))
COMPILER_BINDIR := $(ARDUINO_DATA_DIR)/packages/$(ARDUINO_PACKAGE)/tools/$(COMPILER_TOOLS_DIR)/$(COMPILER_VERSION)/bin
ifeq ($(origin AVR_CXX), undefined)
	COMPILER_NAME := $(strip $(shell ls -1 $(COMPILER_BINDIR) | grep -e 'g++$$' | head -1))
	# We have found the fully-qualified path to the g++ to use.
	AVR_CXX := $(realpath $(COMPILER_BINDIR)/$(COMPILER_NAME))
endif
ifeq ($(origin AVR_AR), undefined)
	AR_NAME := $(strip $(shell ls -1 $(COMPILER_BINDIR) | grep -e 'gcc-ar$$' | head -1))
	AVR_AR := $(realpath $(COMPILER_BINDIR)/$(AR_NAME))
endif
ifeq ($(origin AVR_OBJCOPY), undefined)
	OBJCOPY_NAME := $(strip $(shell ls -1 $(COMPILER_BINDIR) | grep -e 'objcopy$$' | head -1))
	AVR_OBJCOPY := $(realpath $(COMPILER_BINDIR)/$(OBJCOPY_NAME))
endif
ifeq ($(origin AVR_SIZE), undefined)
	SIZE_NAME := $(strip $(shell ls -1 $(COMPILER_BINDIR) | grep -e 'size$$' | head -1))
	AVR_SIZE := $(realpath $(COMPILER_BINDIR)/$(SIZE_NAME))
endif

CXX := $(AVR_CXX)
AR := $(AVR_AR)
OBJCOPY := $(AVR_OBJCOPY)
SIZE := $(AVR_SIZE)

arch_upper := $(strip $(shell echo $(ARCH) | tr [:lower:] [:upper:]))

# Board definitions file for this hardware set.
boards_txt := "$(ARDUINO_DATA_DIR)/packages/$(ARDUINO_PACKAGE)/hardware/$(ARCH)/$(ARCH_VER)/boards.txt"

# Compiler flags we (might) want from arduino-ide's option set.
CFLAGS += -Os # optimize for size.
CFLAGS += -g  # Debug

# Compiler flags we need
CFLAGS += -flto # link-time optimization
CFLAGS += -I$(ARDUINO_DATA_DIR)/packages/$(ARDUINO_PACKAGE)/hardware/$(ARCH)/$(ARCH_VER)/cores/arduino
CFLAGS += -I$(ARDUINO_DATA_DIR)/packages/$(ARDUINO_PACKAGE)/hardware/$(ARCH)/$(ARCH_VER)/variants/$(VARIANT)
CFLAGS += -DARCH_$(arch_upper)

build_mcu := $(strip $(shell grep -e "^$(VARIANT).build.mcu" $(boards_txt) | cut -d '=' -f 2))
CFLAGS += -mmcu=$(build_mcu)

build_board_def := $(strip $(shell grep -e "^$(VARIANT).build.board" $(boards_txt) | cut -d '=' -f 2))
CFLAGS += -DARDUINO_$(build_board_def) # e.g. -DARDUINO_AVR_LEONARDO

build_f_cpu := $(strip $(shell grep -e "^$(VARIANT).build.f_cpu" $(boards_txt) | cut -d '=' -f 2))
CFLAGS += -DF_CPU=$(build_f_cpu)

build_vid := $(strip $(shell grep -e "^$(VARIANT).build.vid" $(boards_txt) | cut -d '=' -f 2))
CFLAGS += -DUSB_VID=$(build_vid)

build_pid := $(strip $(shell grep -e "^$(VARIANT).build.pid" $(boards_txt) | cut -d '=' -f 2))
CFLAGS += -DUSB_PID=$(build_pid)

build_usb_product := $(strip $(shell grep -e "^$(VARIANT).build.usb_product" $(boards_txt) | cut -d '=' -f 2))
CFLAGS += '-DUSB_PRODUCT=$(build_usb_product)'

CFLAGS += -fno-exceptions
CFLAGS += -ffunction-sections
CFLAGS += -fdata-sections

# TODO(aaron): Questionable to enforce by default... do we want to? (arduino-ide does...)
CXXFLAGS += -Wno-error=narrowing

# Include all the CFLAGS for C++ too.
CXXFLAGS += $(CFLAGS)

# Additional flags specific to C++ compilation
CXXFLAGS += -std=gnu++11
CXXFLAGS += -fno-threadsafe-statics

# g++ flags to use for the linker
LINKFLAGS += -g -Os -w -flto -fuse-linker-plugin -Wl,--gc-sections -mmcu=$(build_mcu)

config:
	@echo "Ardiuno build configuration:"
	@echo "===================================="
	@echo "BOARD (fqdn)  : $(BOARD)"
	@echo ""
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
	@echo "AR            : $(AR)"
	@echo "CXX           : $(CXX)"
	@echo "OBJCOPY       : $(OBJCOPY)"
	@echo "SIZE          : $(SIZE)"
	@echo ""
	@echo "Build paths:"
	@echo "===================================="
	@echo "build_dir     : $(build_dir)"
	@echo "src_dirs      : $(src_dirs)"
	@echo "prog_name     : $(prog_name)"
	@echo "TARGET        : $(TARGET)"
	@echo "src_files     : $(src_files)"
	@echo "obj_files     : $(obj_files)"
	@echo ""
	@echo "Options:"
	@echo "===================================="
	@echo 'CFLAGS        : $(CFLAGS)'
	@echo ""
	@echo 'CXXFLAGS      : $(CXXFLAGS)'
	@echo ""
	@echo 'LINKFLAGS     : $(LINKFLAGS)'

clean:
	-rm "$(TARGET)"
	-rm -r "$(build_dir)"
	find . -name "*.o" -delete

core_dir := $(ARDUINO_DATA_DIR)/packages/$(ARDUINO_PACKAGE)/hardware/$(ARCH)/$(ARCH_VER)/cores/arduino
# The src files in build/core/ need to be copied into that dir by the core setup task, so their names can't
# be used as wildcard in depends; rely on the names of the upstream source files in the package
# core_dir.
core_cpp_filenames = $(notdir $(wildcard $(core_dir)/*.cpp))
core_c_filenames = $(notdir $(wildcard $(core_dir)/*.c))
core_asm_filenames = $(notdir $(wildcard $(core_dir)/*.S))
core_obj_files = $(patsubst %.cpp,%.o,$(addprefix $(build_dir)/core/,$(core_cpp_filenames))) \
		$(patsubst %.c,%.o,$(addprefix $(build_dir)/core/,$(core_c_filenames))) \
		$(patsubst %.S,%.o,$(addprefix $(build_dir)/core/,$(core_asm_filenames)))

core_setup_file = $(build_dir)/.copied_core
core_lib = $(build_dir)/core.a

$(core_lib) : $(core_setup_file) $(core_obj_files)
	$(AR) rcs $(core_lib) $(core_obj_files)

# Copy core cpp files to build dir (don't overwrite existing; don't force it to be out of date)
# Because we expect the upstream to barely ever change, instead of making this a phony task (or
# go through the trouble of depending on the actual upstream .cpp files) we just `touch(1)` a
# file to mark that this task is done, so it doesn't continually make our build out of date.
$(core_setup_file):
	mkdir -p "$(build_dir)/core/"
	cp -n "$(core_dir)/"*.cpp "$(build_dir)/core/"
	cp -n "$(core_dir)/"*.c "$(build_dir)/core/"
	cp -n "$(core_dir)/"*.S "$(build_dir)/core/"
	touch $(core_setup_file)

core: $(core_lib)

src_files = $(foreach dir,$(src_dirs),$(wildcard $(dir)/*.cpp))
obj_files = $(patsubst %.cpp,%.o,$(src_files))

eeprom_file = $(build_dir)/$(prog_name).eep
hex_file = $(build_dir)/$(prog_name).hex

# A short bash script that uses the size(1) command to calculate the memory consumption of the
# compiled image:
define SIZE_SCRIPT
DATA=`grep $(build_dir)/size_stats.txt -e "^.data" | tr -s " " | cut -d " " -f 2`; \
TEXT=`grep $(build_dir)/size_stats.txt -e "^.text" | tr -s " " | cut -d " " -f 2`; \
BSS=`grep $(build_dir)/size_stats.txt -e "^.bss" | tr -s " " | cut -d " " -f 2`; \
echo "Global memory used: $$[DATA+BSS] bytes"; \
echo "Sketch size: $$[DATA+TEXT] bytes"
endef

# Main compile/link target. Convert from the ELF executable into files to flash to EEPROM.
image: $(TARGET) $(core_lib) $(eeprom_file) $(hex_file)
	$(SIZE) -A $(TARGET) > $(build_dir)/size_stats.txt
	@bash -c '$(SIZE_SCRIPT)'

# Build the main ELF executable containing user code, Arduino core, any required libraries.
$(TARGET): $(obj_files) $(core_lib)
	$(CXX) $(LINKFLAGS) -o $(TARGET) $(obj_files) $(core_lib) -lm

$(eeprom_file): $(TARGET)
	$(OBJCOPY) -O ihex -j .eeprom --set-section-flags=.eeprom=alloc,load --no-change-warnings \
			--change-section-lma .eeprom=0 $(TARGET) $(eeprom_file)

$(hex_file): $(TARGET) $(eeprom_file)
	$(OBJCOPY) -O ihex -R .eeprom $(TARGET) $(hex_file)

eeprom: $(eeprom_file)

hexfile: $(hex_file)

%.o : %.cpp
	$(CXX) -x c++ -c $(CXXFLAGS) $(CPPFLAGS) $< -o $@

%.o : %.c
	$(CXX) -x c -c $(CFLAGS) $(CPPFLAGS) $< -o $@

%.o : %.S
	$(CXX) -x assembler-with-cpp -c $(CXXFLAGS) $(CPPFLAGS) $< -o $@

.PHONY: config help clean core image eeprom hexfile
