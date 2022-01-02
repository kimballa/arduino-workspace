# (c) Copyright 2021 Aaron Kimball
# 
# Definitions of how to communicate with the debug server
# (pulled directly from dbg.cpp and reformatted).

DBG_END          = '\n' # end of debugger sentence.

DBG_OP_RAMADDR   = '@' # Return data at RAM address
DBG_OP_STACKREL  = '$' # Return data at addr relative to SP.
DBG_OP_CONTINUE  = 'C' # continue execution
DBG_OP_FLASHADDR = 'f' # Return data at Flash address.
DBG_OP_POKE      = 'K' # Insert data to RAM address.
DBG_OP_MEMSTATS  = 'm' # Describe memory usage
DBG_OP_PORT_IN   = 'p' # read gpio pin
DBG_OP_PORT_OUT  = 'P' # write gpio pin
DBG_OP_RESET     = 'R' # Reset CPU.
DBG_OP_REGISTERS = 'r' # Dump registers
DBG_OP_CALLSTACK = 's' # Return call stack info
DBG_OP_TIME      = 't' # Return cpu timekeeping info.
DBG_OP_NONE      = DBG_END

# prefix for logged messages that debugger client should output verbatim to console.
DBG_RET_PRINT    = '>' 

# Character appended to 't' (OP_TIME) to specify units to report.
# e.g. Use the command "tm\n" to get the current millis().
DBG_TIME_MILLIS = 'm' # get time in ms
DBG_TIME_MICROS = 'u' # get time in us
