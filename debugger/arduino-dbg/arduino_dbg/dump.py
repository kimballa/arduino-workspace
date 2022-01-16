# (c) Copyright 2022 Aaron Kimball
#
# Methods for capturing and reloading state from running Arduino.

import arduino_dbg.serialize as serialize

SERIALIZED_STATE_KEY = 'state'

DUMP_SCHEMA_KEY = 'dump_schema'
DUMP_SCHEMA_VER = 1

def capture_dump(debugger, dump_filename):
    """
    Capture registers and SRAM from the device and store in a file locally.

    Assumes that the remote instance is already paused and ready for commands
    from the debugger.
    """

    elf_file_name = debugger.elf_name

    ram_start = debugger.get_arch_conf("RAMSTART")
    ram_end = debugger.get_arch_conf("RAMEND")
    instruction_set = debugger.get_arch_conf("instruction_set")
    gen_reg_count = debugger.get_arch_conf("general_regs")
    byte_order = debugger.get_arch_conf("endian") # 'little' or 'big'

    platform_name = debugger.get_conf('arduino.platform')
    arch_name = debugger.get_conf('arduino.arch')

    # Number of bytes to retrieve from the device at a time
    read_size = 4 # TODO(aaron): Parameterize?

    # what's the memory address where this starts?
    if instruction_set == 'avr':
        # On AVR, we skip the first few bytes from 0 because those are mem-mapped to registers.
        # We'll populate those directly from the register dump.
        # We do read the extended memory-mapped register set from RAM, here, even though it is
        # below RAMSTART.
        #
        # Since we also include $SP and $SREG in registers, we need to sync those
        # mem-mapped positions to the register file values before we write this dump.
        sram_offset = gen_reg_count
    else:
        sram_offset = ram_start


    # list of `bytes` objects to hold memory dump
    sram_bytes = []
    # Retrieve the RAM from the device.
    for read_at in range(sram_offset, ram_end, read_size):
        v = debugger.get_sram(read_at, read_size)
        ram_word = v.to_bytes(read_size, byteorder=byte_order)
        sram_bytes.append(ram_word)
    sram_byte_string = bytearray(b''.join(sram_bytes))

    regs = debugger.get_registers()

    if instruction_set == 'avr':
        # Make sure register-file values for $SP and $SREG are written to the SRAM image
        # at the right mem-mapped-register addresses, so they are consistent on reload.
        spl_port = debugger.get_arch_conf("SPL_PORT")
        has_sph = debugger.get_arch_conf("has_sph")
        if has_sph:
            sph_port = debugger.get_arch_conf("SPH_PORT")
        sreg_port = debugger.get_arch_conf("SREG_PORT")

        avr_port_offset = debugger.get_arch_conf("AVR_PORT_OFFSET")

        sram_byte_string[avr_port_offset + spl_port] = regs["SP"] & 0xFF
        if has_sph:
            sram_byte_string[avr_port_offset + sph_port] = (regs["SP"] >> 8) & 0xFF

        sram_byte_string[avr_port_offset + sreg_port] = regs["SREG"] & 0xFF

    # Gather together the components we need to serialize.
    out = {}
    out['platform'] = platform_name
    out['arch'] = arch_name
    out['elf_file_name'] = elf_file_name
    out['ram_image'] = bytes(sram_byte_string)
    out['ram_image_start'] = sram_offset
    out['registers'] = regs
    out[DUMP_SCHEMA_KEY] = DUMP_SCHEMA_VER

    serialize.persist_config_file(dump_filename, SERIALIZED_STATE_KEY, out)

def load_dump(filename):
    """
    Load a dump file and initialize a debugger instance around it.
    """

    dump_data = serialize.load_config_file(filename, SERIALIZED_STATE_KEY)
    return dump_data




