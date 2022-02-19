# (c) Copyright 2021 Aaron Kimball
#
# Definitions of how to communicate with the debug server
# (pulled directly from dbg.cpp and reformatted).

DBG_END          = '\n'  # end of debugger sentence.

DBG_OP_RAMADDR   = '@'  # Return data at RAM address.
DBG_OP_STACKREL  = '$'  # Return data at addr relative to SP.
DBG_OP_ARCH_SPEC = 'a'  # Report architecture-dependent specification of capabilities or
                        # parameters to the debugger.
DBG_OP_BREAK     = 'B'  # Break execution of the program. Redundant when within interrupted dbg
                        # server but enables confirmation of break state.
DBG_OP_CONTINUE  = 'C'  # Continue execution.
DBG_OP_DEBUGCTL  = 'D'  # Architecture-specific debugger extension sentences.
DBG_OP_FLASHADDR = 'f'  # Return data at Flash address.
DBG_OP_SET_FLAG  = 'L'  # Set bitfield flag (e.g., for breakpoint soft en/dis-able..)
DBG_OP_POKE      = 'K'  # Insert data to RAM address.
DBG_OP_MEMSTATS  = 'm'  # Describe memory usage.
DBG_OP_PORT_IN   = 'p'  # Read gpio pin.
DBG_OP_PORT_OUT  = 'P'  # Write gpio pin.
DBG_OP_RESET     = 'R'  # Reset CPU.
DBG_OP_REGISTERS = 'r'  # Dump registers.
DBG_OP_STEP      = 'S'  # Single-step execution.
DBG_OP_TIME      = 't'  # Return cpu timekeeping info.
DBG_OP_TIME_MILLIS = 'tm'  # Return millisecs since boot.
DBG_OP_TIME_MICROS = 'tu'  # Return microseconds since boot.
DBG_OP_NONE      = DBG_END

# prefix for logged messages that debugger client should output verbatim to console.
DBG_RET_PRINT    = '>'

# Character appended to 't' (OP_TIME) to specify units to report.
# e.g. Use the command "tm\n" to get the current millis().
DBG_TIME_MILLIS = 'm'  # get time in ms
DBG_TIME_MICROS = 'u'  # get time in us

DBG_PAUSE_MSG = "Paused"  # Message sent by server when breakpoint is triggered / interrupt received

DBG_END_LIST = '$'  # A list-based response ends with a '$' on a line by itself.
