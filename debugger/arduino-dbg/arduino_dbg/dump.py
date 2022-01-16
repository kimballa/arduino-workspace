# (c) Copyright 2022 Aaron Kimball
#
# Methods for capturing and reloading state from running Arduino.

import threading
import time

import arduino_dbg.debugger as debugger
import arduino_dbg.io as io
import arduino_dbg.protocol as protocol
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
        # Prepend general-purpose register file data to the beginning of the RAM image.
        reg_bytes = bytearray() 
        for i in range(0, gen_reg_count):
            reg_bytes.append(regs[f'r{i}'])
        sram_byte_string[0:0] = reg_bytes
        sram_offset = 0 # We now have a complete memory image starting at offset 0000h

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

def load_dump(filename, print_q):
    """
    Load a dump file and initialize a debugger instance around it.
    Returns a pair containing (new_debugger, hosted_debug_service).
    """

    # Load the data out of the file...
    dump_data = serialize.load_config_file(filename, SERIALIZED_STATE_KEY)

    # Make a pair of pipes that can communicate with one another.
    (left, right) = io.make_bidi_pipe()

    # Create a new Debugger instance connected to the 'left' pipe.
    # Specify the ELF file associated with this dump and the relevant Arduino platform.
    dbg = debugger.Debugger(dump_data['elf_file_name'], left, print_q)
    dbg.set_conf("arduino.platform", dump_data['platform'])
    dbg.set_process_state(debugger.PROCESS_STATE_BREAK) # It's definitionally always paused.

    # Create a service that acts like the __dbg_service() in C.
    # Connect it to the ram/image and the 'right' pipe.
    dbg_serv = HostedDebugService(dump_data, dbg, right)
    dbg_serv.start() # Start service in a new thread.

    return (dbg, dbg_serv)


class HostedDebugService(object):
    """
    A service that can emulate the __dbg_service() library method locally, from a snapshot of RAM
    and registers.
    """
    def __init__(self, dump_data, debugger, conn):
        self._conn = conn
        self._debugger = debugger

        if dump_data[DUMP_SCHEMA_KEY] > DUMP_SCHEMA_VER:
            raise Exception(f"Cannot load dump schema with version={dump_data[DUMP_SCHEMA_KEY]}")

        self._memory = bytearray(dump_data['ram_image'])
        self._regs = dump_data['registers']

        self.platform = dump_data['platform']
        self.arch = dump_data['arch']
        self.elf_file_name = dump_data['elf_file_name']

        self.stay_alive = True
        self.thread = threading.Thread(target=self.service, name="Hosted debug service")

    def start(self):
        # start this in a new thread.
        self.thread.start()

    def shutdown(self, wait=True):
        """
        Stop the service.
        """
        self.stay_alive = False
        if wait:
            self.thread.join()


    def service(self):
        """
        Emulate the debug service.
        """

        num_gen_registers = self._debugger.get_arch_conf("general_regs")
        endian = self._debugger.get_arch_conf("endian")

        while self.stay_alive:
            while not self._conn.available():
                time.sleep(0.05) # Sleep for 50ms if no data available.
                if not self.stay_alive:
                    return # time to leave

            cmdline = self._conn.readline()
            if not len(cmdline):
                continue
            #print(f"Received: {cmdline}")

            cmd = f'{chr(cmdline[0])}'
            args = self._to_args(cmdline[1:])

            if cmd == protocol.DBG_OP_RAMADDR:
                size = args[0]
                addr = args[1]
                data = int.from_bytes(self._memory[addr:addr+size], byteorder=endian)
                self._send(f'{data:x}')
            elif cmd == protocol.DBG_OP_STACKREL:
                SP = self._regs["SP"]
                size = args[0]
                offset = args[1]
                data = int.from_bytes(self._memory[SP+offset:SP+offset+size], byteorder=endian)
                self._send(f'{data:x}')
            elif cmd == protocol.DBG_OP_BREAK:
                # We're always paused.
                self._send(protocol.DBG_PAUSE_MSG)
            elif cmd == protocol.DBG_OP_CONTINUE:
                self._send_comment("Cannot continue in image debugger")
            elif cmd == protocol.DBG_OP_FLASHADDR:
                size = args[0]
                addr = args[1]
                data = int.from_bytes(self._debugger.get_image_bytes(addr, size))
                self._send(f'{data:x}')
            elif cmd == protocol.DBG_OP_POKE:
                size = args[0]
                addr = args[1]
                val = args[2]
                new_bytes = val.to_bytes(size, byteorder=endian)
                for i in range(0, size):
                    self._memory[addr + i] = new_bytes[i]
            elif cmd == protocol.DBG_OP_MEMSTATS:
                self._send(f'{self._regs["SP"]:x}')
                self._send('0') # malloc_heap_end
                self._send('0') # malloc_heap_start
                self._send('$')
            elif cmd == protocol.DBG_OP_PORT_IN:
                # We silently ignore gpio input
                pass
            elif cmd == protocol.DBG_OP_PORT_OUT:
                # All GPIOs are low in our simulated world.
                # TODO(aaron): We could strobe these during the 'dump' and keep a map of them here.
                self._send("0")
            elif cmd == protocol.DBG_OP_RESET:
                self._send_comment("Cannot reset in image debugger")
            elif cmd == protocol.DBG_OP_REGISTERS:
                for i in range(0, num_gen_registers):
                    reg_nm = f'r{i}'
                    reg_val = self._regs[reg_nm]
                    self._send(f'{reg_val:x}')
                self._send(f'{self._regs["SP"]:x}')
                self._send(f'{self._regs["SREG"]:x}')
                self._send(f'{self._regs["PC"]:x}')
                self._send('$')
            elif cmd == protocol.DBG_OP_TIME:
                # The 'time' is always 0.
                self._send("0")


    # Private helper methods for the main service.

    def _send(self, text):
        if text[-1] != '\n':
            text = text + "\n"
        #print(f'Sending: {text.encode("UTF-8")}')
        self._conn.write(text.encode("UTF-8"))

    def _send_comment(self, comment):
        self._send(protocol.DBG_RET_PRINT + comment)

    def _to_args(self, line):
        """
        Convert the input line to a list of number arguments
        """
        return [int(token) for token in line.strip().split()]

