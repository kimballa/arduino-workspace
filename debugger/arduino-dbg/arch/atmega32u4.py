# Atmel AVR ATmega32u4
#

instruction_set = "avr"

RAMSTART = 0x100
RAMSIZE  = 0xA00
RAMEND   = 0xAFF

FLASHEND = 0x7FFF

# Addresses in .data are at 0x800xxx in the ELF but just `xxx` on-chip.
data_addr_mask = 0xFF7FFFFF

general_regs = 32
has_sph = true
register_list_fmt = [ "general_regs", "SP", "SREG" ]
