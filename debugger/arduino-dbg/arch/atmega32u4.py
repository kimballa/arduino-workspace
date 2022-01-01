# Atmel AVR ATmega32u4
#

instruction_set = "avr"

RAMSTART = 0x100
RAMSIZE  = 0xA00
RAMEND   = 0xAFF

general_regs = 32
has_sph = true
register_list_fmt = [ "general_regs", "SP", "SREG" ]
