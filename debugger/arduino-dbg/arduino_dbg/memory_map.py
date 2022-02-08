# (c) Copyright 2022 Aaron Kimball

"""
Data structures and methods that define the memory map of the device being debugged. Most
embedded CPUs have a segmented physical memory model (separate flash and sram).  Depending
on the particular device, this may be represented as a single flat logical memory map or
multiple aliased segments.
"""

# What kind of memory (mem_type) is the segment?
MEM_FLASH = 'flash'
MEM_RAM = 'RAM'
MEM_EEPROM = 'EEPROM'
MEM_OTHER = 'other'

# Which access mechanism ('read SRAM' or 'read flash/pgmdata') do we use?
ACCESS_TYPE_RAM = 'access_ram'
ACCESS_TYPE_PGM = 'access_flash'


class Segment(object):
    """
    A single segment of system memory which can have separate logical and physical addressing.
    """

    def __init__(self, name, mem_type, access_type, logical_base, physical_base, length):
        self.name = name            # name of the memory segment
        self.mem_type = mem_type    # What kind of memory is this? (MEM_* enum)
        self.access_type = access_type      # How do we access this? (ACCESS_TYPE_* enum)
        self.logical_base = logical_base    # Where does gcc/ld think the segment starts?
        self.physical_base = physical_base  # What actual base addr do we add to an offset
                                            # to ask the device to read the memory?
        self.length = length        # Length of the memory segment

        self.logical_end = logical_base + length
        self.physical_end = physical_base + length

    def __repr__(self):
        length = self.length

        return (f'Segment \'{self.name}\' ({self.mem_type}, {self.access_type}), len={length}:\n'
                f'    0x{self.logical_base:08x} .. 0x{self.logical_end:08x} --> '
                f'0x{self.physical_base:08x} .. 0x{self.physical_end:08x}')

    def get_logical_extent(self):
        """
        Return an interval [start, end) defining the logical memory range for this segment.
        """
        return (self.logical_base, self.logical_end)

    def get_physical_extent(self):
        """
        Return an interval [start, end) defining the physical memory range for this segment.
        """
        return (self.physical_base, self.physical_end)


class MemoryMap(object):
    """
    A list of Segment objects that define the memory model for the CPU.
    """

    def __init__(self):
        self.segments = []

    def __repr__(self):
        return 'Memory map:\n' + '\n'.join(list(map(repr, self.segments)))

    def add_segment(self, seg):
        self.segments.append(seg)

    def validate(self):
        """
        Validate the memory map.
        """

        self.segments.sort(key=lambda seg: seg.logical_base)  # Sort with ascending logical base.

        # Check if the logical memory ranges of any segments overlap. They shouldn't.
        prev = None
        for seg in self.segments:
            if prev is None:
                prev = seg
                continue

            if prev.logical_end > seg.logical_base:
                raise RuntimeError(f'Memory segments have overlapping logical ranges:\n{prev}\n{seg}')

            prev = seg

        return True

    def segment_for_logical_addr(self, addr):
        """
        Given a logical address, determine which segment it belongs to.
        """
        for seg in self.segments:
            (start, end) = seg.get_logical_extent()
            if addr >= start and addr < end:
                return seg

        raise RuntimeError(f'No memory segment for address 0x{addr:x}')

    def logical_to_physical_addr(self, addr):
        """
        Given a logical address (i.e., one we pulled from the ELF file itself) convert it to the
        physical address to request with a segment-aware access mechanism.
        """
        seg = self.segment_for_logical_addr(addr)
        return addr - seg.logical_base + seg.physical_base

    def access_mechanism_for_addr(self, addr):
        """
        Given a logical address, determine which access mechanism (get_sram() or get_flash())
        we should use to access it. (either ACCESS_TYPE_RAM or ACCESS_TYPE_PGM)
        """
        return self.segment_for_logical_addr(addr).access_type


