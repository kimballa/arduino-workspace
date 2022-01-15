# (c) Copyright 2022 Aaron Kimball
#
# Parse DIEs in .debug_info.
# Generates information about datatypes in the program as well as location-to-method(subprogram)
# and location-to-variable mappings.

import elftools.dwarf.constants as dwarf_constants
import elftools.dwarf.dwarf_expr as dwarf_expr
import elftools.dwarf.locationlists as locationlists
from sortedcontainers import SortedDict, SortedList

import arduino_dbg.binutils as binutils
import arduino_dbg.eval_location as eval_location

_INT_ENCODING = dwarf_constants.DW_ATE_signed

PUBLIC = dwarf_constants.DW_ACCESS_public
PROTECTED = dwarf_constants.DW_ACCESS_protected
PRIVATE = dwarf_constants.DW_ACCESS_private

class PCRange(object):
    """
    An interval of $PC values associated with a method implementation.
    """
    def __init__(self, pc_lo, pc_hi, cuns, variable_scope=None, method_name=None):
        self.pc_lo = pc_lo
        self.pc_hi = pc_hi
        self.cuns = cuns # associated CompilationUnitNamespace
        self.method_name = method_name # Method represented by this PCRange, if any.
        self.variable_scope = variable_scope # a MethodInfo or LexicalScope that holds Variables.

    def includes_pc(self, pc):
        return self.pc_lo <= pc and self.pc_hi >= pc

    def __repr__(self):
        s = f'[{self.pc_lo:x}..{self.pc_hi:x}]'
        if self.method_name:
            s += f': {self.method_name}'
        return s

    def __lt__(self, other):
        return self.pc_lo < other.pc_lo or (self.pc_lo == other.pc_lo and self.pc_hi < other.pc_hi)

    def __eq__(self, other):
        return self.pc_lo == other.pc_lo and self.pc_hi == other.pc_hi

    def __ne__(self, other):
        return not self.__eq__(other)

    def __gt__(self, other):
        return other.__lt__(self)

    def __lte__(self, other):
        return self < other or self == other

    def __gte__(self, other):
        return self > other or self == other


class CompilationUnitNamespace(object):
    """
        Compilation Unit-specific namespacing for types, methods, $PC ranges.
    """

    def __init__(self, die_offset, cu, range_lists, debugger):
        self._named_entries = SortedDict() # name -> entry
        self._addr_entries = {}  # DIE offset -> entry
        self._pc_ranges = SortedList() # Range intervals held by methods, etc. within this CU.
        self._range_lists = range_lists # Complete .debug_range data from DWARFInfo object.

        self._die_offset = die_offset
        self._cu = cu
        self._variables = {}
        self._methods = {}

        top_die = cu.get_top_DIE()
        try:
            self._cu_ranges = None # PCRange objects defining the CU itself, if any.
            self._low_pc = top_die.attributes['DW_AT_low_pc'].value
            self._high_pc = top_die.attributes['DW_AT_high_pc'].value
        except KeyError:
            # Ordinarily location ranges are relative to the compilation unit base address,
            # but if the compilation unit is itself defined as a set of ranges, they are absolute.
            # Either way, we need _low_pc to be an integer.
            self._low_pc = 0
            self._high_pc = None

            # Compilation unit covers noncontiguous range or otherwise unknown extent.
            # CU may have multiple intervals in DW_AT_ranges.
            #print(top_die)
            range_data_offset = None
            range_attr = top_die.attributes.get('DW_AT_ranges')
            if range_attr:
                range_data_offset = range_attr.value
            if range_data_offset and range_lists:
                rangelist = range_lists.get_range_list_at_offset(range_data_offset)
                self._cu_ranges = SortedList()
                for r in rangelist:
                    #debugger.verboseprint(f'Extracted range for CU: {r.begin_offset:04x}' +
                    #    f' -- {r.end_offset:04x}')
                    self._cu_ranges.add(PCRange(r.begin_offset, r.end_offset, self))


        self.expr_parser = dwarf_expr.DWARFExprParser(cu.structs)
        self._debugger = debugger

    def getCU(self):
        return self._cu

    def getExprMachine(self, location_expr_data, regs):
        """
        Return an expression evaluation machine ready to process the specified location info.
        @param location_expr_data the result of a LocationParser (either a LocationExpr or
        a list of LocationEntry/BaseAddressEntry objects).

        @return the ready-to-go expr eval machine loaded with the right location expression opcodes
        for the current PC location, or None if there is no location data valid at the current PC.
        """

        parser = self.expr_parser
        location_expr_bytes = None
        if isinstance(location_expr_data, locationlists.LocationExpr):
            # It's a single list<int> representing the universal location expression for this var.
            location_expr_bytes = location_expr_data.loc_expr
        else:
            # It's a list of pc-dependent location entries.
            pc = regs["PC"]
            base_addr = self._low_pc
            for loc_list_entry in location_expr_data:
                if isinstance(loc_list_entry, locationlists.BaseAddressEntry):
                    # I *think* this means the list in .debug_loc is not relative to CU start,
                    # but is now relative to this value. Is this *also* relative to CU start,
                    # or is it supposed to be absolute? Don't have example data to work with.
                    base_addr = loc_list_entry.base_address
                else:
                    interval_low = base_addr + loc_list_entry.begin_offset
                    interval_high = base_addr + loc_list_entry.end_offset
                    if pc >= interval_low and pc < interval_high:
                        # We found it.
                        location_expr_bytes = loc_list_entry.loc_expr
                        break

        if location_expr_bytes is None:
            # No location entry info mapped to current $PC.
            return None

        return eval_location.DWARFExprMachine(
            parser.parse_expr(location_expr_bytes),
            regs, self._debugger)


    def getDebugger(self):
        return self._debugger

    def define_pc_range(self, pc_lo, pc_hi, scope, method_name):
        self._pc_ranges.add(PCRange(pc_lo, pc_hi, self, scope, method_name))

    def cu_contains_pc(self, pc):
        """
        Return True if the PC is in-range for this CU, or if the CU contains no PC info whatsoever.
        """
        if self._low_pc is not None and self._high_pc is not None:
            return pc >= self._low_pc and pc < self._high_pc
        elif self._cu_ranges is not None:
            for r in self._cu_ranges:
                if r.includes_pc(pc):
                    return True
            return False
        else:
            # No PC range info whatsoever associated w/ this compilation unit. Assume True.
            return True

    def is_cu_range_defined(self):
        """
        Return True if this CU declares bookend PC range information.
        """
        return (self._low_pc is not None and self._high_pc is not None) or \
            self._cu_ranges is not None

    def get_ranges_for_pc(self, pc):
        """
        Return all PCRanges for methods, lexical scopes, etc. in this CU that include $PC.
        Returned in sorted order.
        """
        out = SortedList()

        if not self.cu_contains_pc(pc):
            # Out of bounds.
            return out

        # TODO(aaron): Consider using self._pc_ranges.bisect_left() on a PCRange(pc,pc)
        # to pinpoint in O(log(N)) time instead of O(n)
        # http://www.grantjenks.com/docs/sortedcontainers/sortedlist.html#sortedcontainers.SortedList.bisect_right
        for pcr in self._pc_ranges:
            if pcr.includes_pc(pc):
                out.add(pcr)
            elif pcr.pc_lo > pc:
                # We've walked past anything relevant.
                break
        return out

    def add_entry(self, typ, name, addr):
        if name and not self._named_entries.get(name):
            self._named_entries[name] = typ

        if addr:
            try:
                self._addr_entries[addr]
                # Error: if we found an entry, we're trying to multiply-define it.
                raise Exception(f"Already defined entry at addr {addr:x}")
            except KeyError:
                # Typical case: haven't yet bound this addr to an entry. Do so here.
                self._addr_entries[addr] = typ

    def entry_by_name(self, name):
        return self._named_entries.get(name) or None

    def entry_by_addr(self, addr):
        return self._addr_entries.get(addr) or None

    def has_addr_entry(self, addr):
        return self.entry_by_addr(addr) is not None

    def addVariable(self, var):
        self._variables[var.name] = var

    def getVariable(self, varname):
        return self._variables.get(varname)

    def getVariables(self):
        return self._variables.items()

    def addMethod(self, methodInfo):
        self._methods[methodInfo.method_name] = methodInfo

    def getMethod(self, methodName):
        return self._methods.get(methodName)

    def __repr__(self):
        return f'Compilation unit (@offset {self._die_offset:x})'

class GlobalScope(object):
    """
        Container for the globally-accessible names (types, vars, methods, etc.)
        Each of these elements formally sits within some CompilationUnit but is
        also accessible here.
    """

    def __init__(self):
        self._variables = {}
        self._methods = {}

    def addVariable(self, var):
        self._variables[var.name] = var

    def getVariable(self, varname):
        return self._variables.get(varname)

    def getVariables(self):
        return self._variables.items()

    def addMethod(self, methodInfo):
        self._methods[methodInfo.method_name] = methodInfo

    def getMethod(self, methodName):
        return self._methods.get(methodName)

    def getOrigin(self):
        return self

    def getContainingScope(self):
        return None

    def __repr__(self):
        return 'GlobalScope'



class PrgmType(object):
    """
    Basic root object for a datatype or other DIE within the debugged program.
    """

    def __init__(self, name, size, parent_type=None):
        self.name = name
        self.size = size
        if size == 'int':
            raise Exception("wtf type")
        self._parent_type = parent_type


    def parent_type(self):
        """
        Return the type underlying this one, if any, or None otherwise.
        """
        return self._parent_type

    def is_type(self):
        """
        Return True if this is actually a true type definition; not a var/method decl
        """
        return True

    def __repr__(self):
        return f'{self.name}'

class PrimitiveType(PrgmType):
    """
    A fundamental type in the programming language (int, long, float, etc).
    """

    def __init__(self, name, size, signed=False):
        PrgmType.__init__(self, name, size)
        self.signed = signed

    def __repr__(self):
        return self.name


class ConstType(PrgmType):
    """
    A const form of another type
    """
    def __init__(self, base_type):
        name = f'const {base_type.name}'
        PrgmType.__init__(self, name, base_type.size, base_type)
        self.name = name

    def __repr__(self):
        return self.name

class PointerType(PrgmType):
    """
    A pointer to an item of type T.
    """
    def __init__(self, base_type):
        name = f'{base_type.name}*'
        PrgmType.__init__(self, name, _encodings[_INT_ENCODING], base_type)
        self.name = name

    def __repr__(self):
        return f'{self.name}'

class ReferenceType(PrgmType):
    """
    A reference to an item of type T.
    """
    def __init__(self, base_type):
        name = f'{base_type.name}&'
        PrgmType.__init__(self, name, _encodings[_INT_ENCODING], base_type)
        self.name = name

    def __repr__(self):
        return f'{self.name}'

class EnumType(PrgmType):
    """
    An enumeration of constant->value mappings.
    """

    def __init__(self, enum_name, base_type, mappings={}):
        PrgmType.__init__(self, 'enum ' + enum_name, base_type.size, base_type)
        self.enum_name = enum_name
        self.enums = {}
        for (token, val) in mappings.items():
            self.enums[token] = val

    def addEnum(self, token, val):
        self.enums[token] = val

    def enum(self, token):
        """
        Return the value for the given enum label.
        """
        return self.enums[token]

    def nameOf(self, val):
        """
        Return the enum label for the given value.
        """
        for (token, mapval) in self.enums.items():
            if val == mapval:
                return token
        return None

    def __repr__(self):
        s = f'enum {self.enum_name} [size={self.size}] {{\n  '
        mappings = []
        for (token, val) in self.enums.items():
            mappings.append(f"{token} = {val}")
        s += ",\n  ".join(mappings)
        s += f'\n}}'
        return s

class ArrayType(PrgmType):
    """
    An array of items.
    """

    def __init__(self, base_type, length=0):
        PrgmType.__init__(self, f'{base_type.name}[]', base_type.size, base_type)
        self.length = length

    def setLength(self, len):
        self.length = len

    def __repr__(self):
        return f'{self.parent_type()}[{self.length}]'

class AliasType(PrgmType):
    """
    A typedef or other alias.
    """
    def __init__(self, alias, base_type):
        PrgmType.__init__(self, alias, base_type.size, base_type)

    def __repr__(self):
        return f'typedef {self.parent_type().name} {self.name}'


class LexicalScope(object):
    """
        A lexical scope (bound to a PCRange) - container for Variable definitions in a method.
    """

    def __init__(self, origin=None, containingScope=None):
        """
            * origin is the resolved abstract_origin object for this scope.
            * containingScope is a LexicalScope or Method that encloses this one, if any.
        """
        self._origin = origin
        self._containingScope = containingScope
        self._variables = {}

    def addVariable(self, var):
        self._variables[var.name] = var

    def getVariable(self, varname):
        return self._variables.get(varname)

    def getVariables(self):
        return self._variables.items()

    def getOrigin(self):
        return self._origin or self

    def getContainingScope(self):
        return self._containingScope

    def evalFrameBase(self, regs):
        scope = self.getContainingScope()
        if not scope:
            return None
        return scope.evalFrameBase(regs)

    def addFormal(self, arg):
        # Pass formal argument on to containing Method.
        if self._containingScope:
            self._containingScope.addFormal(arg)

    def getFormals(self):
        return []

    def __repr__(self):
        return 'LexicalScope'


class MethodPtrType(PrgmType):
    """
    Pointer-to-method type. Not an actual method decl/def'n.
    """
    def __init__(self, name, return_type=None, member_of=None):
        PrgmType.__init__(self, name, 0, None)
        self.return_type = return_type or _VOID
        self.member_of = member_of
        self.formal_args = []

    def addFormal(self, arg):
        if arg is None:
            arg = FormalArg('', _VOID, None)
        self.formal_args.append(arg)

    def __repr__(self):
        formals = ', '.join(map(lambda arg: f'{arg}', self.formal_args))
        if self.member_of:
            member = self.member_of.name + '::'
        else:
            member = ''
        return f'{self.return_type.name}({member}*{self.name})({formals})'




class MethodInfo(PrgmType):
    def __init__(self, method_name, return_type, cuns, member_of=None, virtual=0,
            accessibility=1, is_decl=False, is_def=False, origin=None):

        if method_name is None:
            name = None
        else:
            name = f'{return_type.name} '
            if member_of:
                name += f'{member_of.name}::'
            name += f'{method_name}()'

        PrgmType.__init__(self, name, 0, None)

        self.method_name = method_name
        self.return_type = return_type
        self.member_of = member_of
        self.virtual = virtual
        self.accessibility = accessibility

        self._cuns = cuns

        # Methods may appear multiple times throughout the .debug_info.
        # A forward-declared prototype signature will have is_decl=True.
        # The method proper, with its body will have is_def=True.
        # An inline-defined method in a class { ... } can be is_decl and is_def=True.
        # An inline instance of a method will have both set to False.
        # _origin should point back to the canonical declaration instance of the method.
        self.is_decl = is_decl # Is this the _declaration_ of the method?
        self.is_def = is_def   # Is this the _definition_ of the method?

        self._variables = {}
        self._origin = origin
        self.formal_args = []
        self.frame_base = None

    def addFormal(self, arg):
        if arg is None:
            arg = FormalArg('', _VOID, None)
        arg.setScope(self)
        self.formal_args.append(arg)

    def getFormals(self):
        return self.formal_args

    def addVariable(self, var):
        self._variables[var.name] = var

    def getVariable(self, varname):
        return self._variables.get(varname)

    def getVariables(self):
        return self._variables.items()

    def setOrigin(self, origin):
        self._origin = origin

    def getOrigin(self):
        return self._origin or self

    def setFrameBase(self, frame_base):
        """ Set the LocationExpr / LocationList for the frame pointer """
        self._frame_base = frame_base

    def evalFrameBase(self, regs):
        """
        Evaluate the location info in frame_base to get the canonical frame addr (CFA)
        for the current method. Used in the FBREG operation for a framebase-relative
        variable storage location.
        """
        loc = self._location # TODO - or self.getOrigin()._location??
        if loc is None:
            return None

        expr_machine = self._cuns.getExprMachine(loc, regs)
        if expr_machine is None:
            return None
        return expr_machine.access(self.size)

    def is_type(self):
        return False

    def __repr__(self):
        s = ''
        if self.accessibility == PUBLIC:
            s += 'public '
        elif self.accessibility == PROTECTED:
            s += 'protected '
        elif self.accessibility == PRIVATE:
            s += 'private '

        if self.virtual:
            s += 'virtual '
        s += f'{self.return_type.name} {self.method_name}('
        s += ', '.join(map(lambda arg: f'{arg}', self.formal_args))
        s += ')'
        if self.virtual == dwarf_constants.DW_VIRTUALITY_pure_virtual:
            # pure virtual.
            s += ' = 0'
        return s

class FormalArg(object):
    def __init__(self, name, arg_type, cuns, origin=None, location=None, const_val=None, scope=None):
        self.name = name
        self.arg_type = arg_type
        self._cuns = cuns
        self._origin = origin
        self._location = location
        self._const_val = const_val
        self._scope = scope

    def __repr__(self):
        return f'{self.arg_type.name} {self.name}'

    def setOrigin(self, origin):
        self._origin = origin

    def getOrigin(self):
        return self._origin or self

    def setScope(self, scope):
        self._scope = scope

    def getAddress(self, regs):
        """
        Evaluate the location info to get the memory address of this variable.

        @param regs the current register state for the frame.
        @return the memory and register location info for the variable (in the format
            returned by the DWARFExprMachine), or None if no such info is available.
        """
        loc = self._location or self.getOrigin()._location
        if loc is None:
            return None

        expr_machine = self._cuns.getExprMachine(loc, regs)
        if expr_machine is None:
            return None
        expr_machine.setScope(self._scope)
        return expr_machine.eval()

    def getValue(self, regs):
        """
        Evaluate the location info to get the current value of this variable.

        @param regs the current register state for the frame.
        @return the value of the variable, or None if no such info is available.
        """
        if self._const_val is not None:
            # It got hardcoded in the end.
            return self._const_val

        loc = self._location or self.getOrigin()._location
        if loc is None:
            return None

        expr_machine = self._cuns.getExprMachine(loc, regs)
        if expr_machine is None:
            return None
        expr_machine.setScope(self._scope)
        return expr_machine.access(self.arg_type.size)



class FieldType(PrgmType):
    def __init__(self, field_name, member_of, field_type, offset, accessibility):
        PrgmType.__init__(self, f'{member_of.name}::{field_name} {field_type}', field_type.size, field_type)
        self.field_name = field_name
        self.member_of = member_of
        self.offset = offset
        self.accessibility = accessibility

    def is_type(self):
        return False

    def __repr__(self):
        if self.accessibility == PUBLIC:
            acc = 'public'
        elif self.accessibility == PROTECTED:
            acc = 'protected'
        elif self.accessibility == PRIVATE:
            acc = 'private'
        else:
            acc = 'public' # Assume public by default.

        return f'{acc} {self.parent_type().name} {self.field_name} ' + \
            f'[size={self.parent_type().size}, offset={self.offset:#x}]'

class ClassType(PrgmType):
    """
    A class or struct.
    """
    def __init__(self, class_name, size, base_type):
        # TODO(aaron): how does 'base_type' interact with multiple inheritance? diamond inheritance?
        PrgmType.__init__(self, 'class ' + class_name, size, base_type)

        self.class_name = class_name
        self.methods = []
        self.fields = []


    def addMethod(self, method_type):
        self.methods.append(method_type)

    def getMethod(self, methodName):
        for m in self.methods:
            if m.method_name == methodName:
                return m
        return None

    def addField(self, field_type):
        self.fields.append(field_type)

    def getField(self, fieldName):
        for f in self.fields:
            if f.field_name == fieldName:
                return f
        return None

    def __repr__(self):
        s = f'{self.name}'
        if self.parent_type():
            s += f' <subtype of {self.parent_type().name}>'
        s += ' {\n'
        if len(self.methods) + len(self.fields) > 0:
            s += '  '
        s += ';\n  '.join(map(lambda m: f'{m}', self.methods + self.fields))
        if len(self.methods) + len(self.fields) > 0:
            s += '\n'
        s += '}'
        return s

class VariableInfo(PrgmType):
    """
    Info record for a variable (not struct field) defined globally/statically in a file or
    locally within a method.

    A single variable may have multiple VariableInfo records associated with it to distinguish
    forward declaration vs the resolved definition. Local variables within a method that is
    inlined to multiple locations may also have multiple definitions.
    """
    def __init__(self, var_name, var_type, cuns, location=None, is_decl=False, is_def=False,
            origin=None, scope=None):

        PrgmType.__init__(self, var_name, var_type.size)
        self.var_name = var_name
        self.var_type = var_type
        self._cuns = cuns           # CompilationUnitNS owner of this DIE (needed to eval locations)
        self._location = location   # Expression (or pc range -> expr list) defining how to find
                                    # the value in the prgm memory / regs
        self._const_val = None

        self.is_decl = is_decl      # See MethodInfo for definitions of these two flags.
        self.is_def = is_def

        self._origin = origin        # Resolved DW_AT_abstract_origin, if any, poiting decl->def
        self._scope = scope

    def __repr__(self):
        return f'{self.var_type.name} {self.var_name}'

    def setOrigin(self, origin):
        self._origin = origin

    def getOrigin(self):
        # TODO(aaron): Should this be recursive?
        return self._origin or self

    def getType(self):
        return self.var_type

    def getAddress(self, regs):
        """
        Evaluate the location info to get the memory address of this variable.

        @param regs the current register state for the frame.
        @return the memory and register location info for the variable (in the format
            returned by the DWARFExprMachine), or None if no such info is available.
        """
        loc = self._location or self.getOrigin()._location
        if loc is None:
            return None

        expr_machine = self._cuns.getExprMachine(loc, regs)
        if expr_machine is None:
            return None
        expr_machine.setScope(self._scope)
        return expr_machine.eval()

    def getValue(self, regs):
        """
        Evaluate the location info to get the current value of this variable.

        @param regs the current register state for the frame.
        @return the value of the variable, or None if no such info is available.
        """
        if self._const_val is not None:
            # It got hardcoded in the end.
            return self._const_val

        loc = self._location or self.getOrigin()._location
        if loc is None:
            return None

        expr_machine = self._cuns.getExprMachine(loc, regs)
        if expr_machine is None:
            return None
        expr_machine.setScope(self._scope)
        return expr_machine.access(self.size)

    def setConstValue(self, val):
        """
        This variable has been const-reduced.
        """
        self._const_val = val

    def is_type(self):
        return False



_encodings = {} # Global encodings table (encodingId -> PrgmTypE)
_cu_namespaces = [] # Set of CompilationUnitNamespace objects.

_global_syms = GlobalScope() # vars/methods tagged DW_AT_external visible from any CU.

def types(prefix=None):
    """
    Iterator over all typedefs.

    If prefix is specified, returns all type names that begin with 'prefix'.
    """
    if prefix is None or len(prefix) == 0:
        nextfix = None # Empty str prefix means return all types.
        prefix = None
    else:
        # Increment the last char of the string to get the first possible type
        # after the matching set.
        last_char = prefix[-1]
        next_char = chr(ord(last_char) + 1)
        nextfix = prefix[0:-1] + next_char

    for cuns in _cu_namespaces:
        # Do a prefix search.
        #
        # Note that this will efficiently search for appropriate keys across all
        # compilation units, but it will yield items in sorted order only per-CU; a
        # globally sorted list requires yielding all items and then sorting the results.
        for name in cuns._named_entries.irange(prefix, nextfix, inclusive=(True, False)):
            typ = cuns._named_entries[name]
            if typ.is_type():
                yield (name, typ)

KIND_TYPE = 1
KIND_METHOD = 2
KIND_VARIABLE = 3

def getNamedDebugInfoEntry(name, pc):
    """
    Return the debug info object for a given name in the compilation unit associated with $PC.
    This can be a named type, a method, or a variable.
    This method returns a pair of (KIND, entry).
    """
    pc_ranges = SortedList()
    search_cuns = None
    for cuns in _cu_namespaces:
        if cuns.cu_contains_pc(pc) and cuns.is_cu_range_defined():
            # The above update is the exclusive namespace search we need.
            # Don't keep searching.
            search_cuns = cuns
            break
        elif cuns.cu_contains_pc(pc):
            # Try to search method-by-method to see if this cuns covers it.
            pc_ranges.update(cuns.get_ranges_for_pc(pc))
            if len(pc_ranges) > 0:
                # Yes, we found it.
                search_cuns = cuns
                break

    if search_cuns is None:
        return None # We fell off the edge into outer space?

    # search_cuns is the CompilationUnitNamespace that encloses the $PC.

    # Use the various lookup tables available to us:
    # we are either looking up a literal type, a signature for a method name, or a type for a var.
    typ = search_cuns.getMethod(name)
    if typ:
        return (KIND_METHOD, typ)

    typ = search_cuns.getVariable(name)
    if typ:
        return (KIND_VARIABLE, typ)

    typ = search_cuns.entry_by_name(name)
    if typ:
        return (KIND_TYPE, typ)

    # Also search globals if not found locally.
    global_entry = _global_syms.getVariable(name)
    if global_entry:
        return (KIND_VARIABLE, global_entry)

    global_entry = _global_syms.getMethod(name)
    if global_entry:
        return (KIND_METHOD, global_entry)

    return (None, None)


def getMethodsForPC(pc):
    """
    Return a list identifying method(s) that contain the specified $PC.
    If the PC is in a "normal" method, this will be a singleton list.
    However, if the method (as identified on the stack frame) body contains other inlined methods
    (which may happen recursively), this provides a list from narrowest to widest of the
    method(s) where the PC currently is.

    e.g. if we have:
    inline void inner2() { ...; /* $PC */; ... }
    inline void inner1() { ...; inner2(); ... }
    void outermost() {
        inner1();
    }

    then getMethodsForPC($PC) will return ['inner2', 'inner1', 'outermost']
    """
    pc_ranges = SortedList()
    for cuns in _cu_namespaces:
        pc_ranges.update(cuns.get_ranges_for_pc(pc))

    out = []
    for pcr in pc_ranges:
        if pcr.method_name:
            out.append(pcr.method_name)

    #print(f"inline chains: {pc:x} -> {out}")
    out.reverse()
    return out

def getScopesForPC(pc, include_global=False):
    """
    Return a list of methods, inlined methods, and lexical scopes that enclose the specified PC.
    This output list is in no particular order.

    @param pc the current program counter value for the frame.
    @param include_global if true includes a GlobalScope object showing what globals can be
        accessed from the $PC.
    """
    out = {}
    pc_ranges = SortedList()

    for cuns in _cu_namespaces:
        pc_ranges.update(cuns.get_ranges_for_pc(pc))

        if cuns.cu_contains_pc(pc) and cuns.is_cu_range_defined():
            # The above update is the exclusive namespace search we need.

            # If include_globals is true, then include the CUNS itself as a containing scope..
            if include_global:
                out[cuns] = True

            # Don't keep searching.
            break


    for pcr in pc_ranges:
        if pcr.variable_scope:
            # Save variable scopes as dict keys to get the unique set,
            # as a lexical scope's variable_scope may just point to the enclosing method.
            out[pcr.variable_scope] = True

    if include_global:
        # if include_globals, include the GlobalScope object too.
        out[_global_syms] = True

    return list(out.keys())

def _populateEncodings(int_size):
    """
    Set up initial primitive types that also map to the 'encoding' attr of some DIE types.
    """
    def _add(n, typ):
        if n is not None:
            _encodings[n] = typ

    global _VOID
    _VOID = PrimitiveType('void', 0)
    _add(0, _VOID)
    _add(1, PrimitiveType('<ptr>', int_size))
    _add(2, PrimitiveType('bool', 1))
    # 3 is 'complex float'
    _add(4, PrimitiveType('float', 4))
    _add(5, PrimitiveType('int', int_size, signed=True))
    _add(6, PrimitiveType('char', 1, signed=True))
    _add(7, PrimitiveType('unsigned int', int_size, signed=False))
    _add(8, PrimitiveType('unsigned char', 1, signed=False))
    _add(0x10, PrimitiveType('<UTF8_string>', 1))
    _add(0x12, PrimitiveType('<ASCII_string>', 1))

def parseTypesFromDIE(die, cuns, context={}):
    """
        Parse a DIE within a specific CompilationUnitNamespace

        @param die the DIE to process.
        @param cuns the current CompilationUnitNamespace
        @param context additional context for nested DIE processing.
    """
    cu = cuns.getCU()
    cu_offset = cu.cu_offset

    def _fresh_context():
        """
            Return a context that is 'clean' of any nested DIE state, for use in non-local
            parsing requirements.
        """
        ctxt = {}
        for key in _default_context_keys:
            ctxt[key] = context[key]

        return ctxt

    def _lookup_type(param='type'):
        """
            Look up the 'DW_AT_type' attribute and resolve it to a PrgmType within the current
            CU Namespace..
        """
        # This attr value is offset relative to the compile unit, but it refers
        # to elements of our address-oriented lookup table which is global across
        # all addresses/offsets within the .dwarf_info.
        try:
            addr = die.attributes['DW_AT_' + param].value + cu_offset
        except KeyError:
            return None # No 'type' field for this DIE.

        if addr == die.offset:
            # Struct/class can refer to their own addr as containing_type. Do nothing.
            return None
        elif not cuns.has_addr_entry(addr):
            # We haven't processed this address yet; it's e.g. a forward reference.
            # We need to process that entry before returning a type to the caller of this method.
            sub_die = cu.get_DIE_from_refaddr(addr)
            parseTypesFromDIE(sub_die, cuns, _fresh_context())

        return cuns.entry_by_addr(addr)

    def _resolve_abstract_origin():
        """
        Trace the abstract_origin property of this DIE back up to the root of the abstract_origin
        trail.
        """
        typ = _lookup_type('abstract_origin')
        return typ.getOrigin()

    def _add_entry(typ, name, addr):
        cuns.add_entry(typ, name, addr)

    def dieattr(name, default_value=None):
        """
            Look up an attribute within the current DIE; if not found, use default_value.
        """
        try:
            val = die.attributes['DW_AT_' + name].value
            if isinstance(val, bytes):
                val = val.decode("utf-8")
            return val
        except KeyError:
            return default_value

    def _get_locations(attr_name='location'):
        """
        Return location expression or a list of LocationEntry elements.
        """
        try:
            attr = die.attributes['DW_AT_' + attr_name]
            return locationlists.LocationParser(context['loc_lists']).parse_from_attribute(
                attr, context['dwarf_ver'])
        except KeyError:
            return None


    if not die.tag:
        return # null DIE to terminate nested set.
    elif cuns.has_addr_entry(die.offset):
        return # Our seek-driven parsing has already parsed this entry, don't double-process.

    total_off = die.offset + cu_offset
    #print(f"Loading DIE {die.tag} {dieattr('name')} at offset {die.offset:x} (CU offset {cu_offset:x})")
    #print(die)

    if dieattr('name') and cuns.entry_by_name(dieattr('name')):
        # We're redefining a type name that already exists.
        # Just copy the existing definition into this address.
        _add_entry(cuns.entry_by_name(dieattr('name')), None, die.offset)
        return


    if die.tag == 'DW_TAG_base_type':
        # name, byte_size, encoding
        # This could be a true base/primitive type, or a typedef of a primitive type.
        # These may be repeated over multiple compilation units.
        #
        # If it has the same name as the pre-installed PrimitiveType for its encoding,
        # it's just the primitive type all over again.
        # If it has a different name and size, it's a fundamental C type we didn't already add.
        # If it has a different name and same size it's a typedef.
        name = dieattr('name')
        size = dieattr('byte_size')
        prim = _encodings[dieattr('encoding')]

        if name == prim.name and size == prim.size:
            # benign redundant definition.
            # register the common type object at this addr too.
            _add_entry(prim, None, die.offset)
        elif size == prim.size:
            _add_entry(AliasType(name, prim), name, die.offset)
        else:
            _add_entry(PrimitiveType(name, size), name, die.offset)

    elif die.tag == 'DW_TAG_const_type':
        base = _lookup_type() or _VOID
        const = ConstType(base)
        _add_entry(const, const.name, die.offset)
    elif die.tag == 'DW_TAG_volatile_type':
        # define 'volatile foo' as an alias to type foo.
        base = _lookup_type()
        _add_entry(base, 'volatile ' + base.name, die.offset)
    elif die.tag == 'DW_TAG_pointer_type':
        base = _lookup_type() or _VOID
        ptr = PointerType(base)
        _add_entry(ptr, ptr.name, die.offset)
    elif die.tag == 'DW_TAG_reference_type':
        base = _lookup_type() or _VOID
        ref = ReferenceType(base)
        _add_entry(ref, ref.name, die.offset)
    elif die.tag == 'DW_TAG_typedef':
        # name, type
        base = _lookup_type()
        name = dieattr('name')
        _add_entry(AliasType(name, base), name, die.offset)
    elif die.tag == 'DW_TAG_array_type':
        # type
        base = _lookup_type()
        arr = ArrayType(base)
        _add_entry(arr, arr.name, die.offset) # TODO: if this causes collision problems, remove arr.name.
        ctxt = context.copy()
        ctxt['array'] = arr
        for child in die.iter_children():
            parseTypesFromDIE(child, cuns, ctxt)
    elif die.tag == 'DW_TAG_subrange_type': # Size of array
        # [lower_bound=0], upper_bound
        lower = dieattr("lower_bound", 0)
        upper = dieattr("upper_bound")
        length = upper - lower + 1
        context['array'].setLength(length)
    elif die.tag == 'DW_TAG_enumeration_type':
        # name, type, byte_size
        name = dieattr('name')
        base = _lookup_type()
        enum = EnumType(name, base)
        _add_entry(enum, enum.name, die.offset)
        ctxt = context.copy()
        ctxt['enum'] = enum
        for child in die.iter_children():
            parseTypesFromDIE(child, cuns, ctxt)
    elif die.tag == 'DW_TAG_enumerator': # Member of enumeration
        # name, const_value
        name = dieattr('name')
        val = dieattr('const_value')
        context['enum'].addEnum(name, val)
    elif die.tag == 'DW_TAG_structure_type' or die.tag == 'DW_TAG_class_type': # class or struct
        # name, byte_size, containing_type
        # TODO: can have 1+ DW_TAG_inheritance that duplicate or augment containing_type
        name = dieattr('name')
        size = dieattr('byte_size')

        if name and cuns.entry_by_name(name) is not None:
            # This is a redefinition of a type that already exists. Just install it here.
            # TODO: Do we need to recurse and handle the redundant 'member', vtbl_ptr, etc.s?
            _add_entry(getType(name), None, die.offset)
            return

        parent_type_offset = dieattr("containing_type", None)
        if parent_type_offset is None:
            parent_type = None
        else:
            parent_type = _lookup_type("containing_type")
        class_type = ClassType(name, size, parent_type)
        _add_entry(class_type, name, die.offset)
        ctxt = context.copy()
        ctxt['class'] = class_type
        for child in die.iter_children():
            parseTypesFromDIE(child, cuns, ctxt)
    elif die.tag == 'DW_TAG_member':
        # name, type, data_member_location
        # accessibility (1=public, 2=protected, 3=private)
        # data_member_location is a multibyte sequence:
        # [23h, Xh] means 'at offset Xh' (DW_OP_plus_uconst)
        name = dieattr('name')
        base = _lookup_type()
        data_member_location = dieattr('data_member_location')

        # class member offsets are technically stack machine exprs that require full
        # evaluation. g++ seems to encode them all as DW_OP_plus_uconst [offset], but
        # we've got the ability to calculate more complicated patterns, so long as they
        # don't require access to current memory or registers here (which they shouldn't,
        # as part of a static type definition). The expr assumes the address of the
        # object is already on the expr stack to provide a true member address; we push '0'
        # here as a starting stack to get a member offset rather than a member address.
        #
        # nb evaluating for offset here means doing so without a $PC, so we're assuming
        # it's a single location expr and not a location_list. The latter _seems_ impossible
        # for a field offset location to be PC-dependent, but maybe not?
        expr_machine = cuns.getExprMachine(
            locationlists.LocationExpr(data_member_location), {})
        expr_machine.push(0)
        offset_list = expr_machine.eval()
        (offset, _) = offset_list[0]

        accessibility = dieattr('accessibility', 1)
        field = FieldType(name, context.get("class"), base, offset, accessibility)
        context['class'].addField(field)
        _add_entry(field, None, die.offset)
    elif die.tag == 'DW_TAG_subprogram':
        # (Can be a function on its own, or a member method of a class)
        # name, [accessibility=1], [virtuality=0]
        # object_pointer <-- points to implicit 'this' formal arg.
        #
        # In addition to using subprogram to define a method type/signature, we use subprogram and
        # inlined_subroutine to resolve a $PC to the right compilation unit to understand the type
        # definitions relevant to the current stack frame/method.
        #
        # * A subprogram can have a low_pc -- high_pc range
        # * It can also have a `specification` that points to another subprogram.
        # * An inlined_subroutine can have a low_pc--high_pc range.
        #   It has an abstract_origin that points to a subprogram canonically defining it within a
        #   CU. You may need to recursively follow 'specification' from there to get the real CU.
        name = dieattr('name')

        # 'name' itself is going to be a mangled name, which isn't super useful to the user.
        # Get this in demangled form.
        demangled = binutils.demangle(name, hide_params=True)
        if demangled:
            # 'demangled' may now be in the form '/[ClassName::]+methodName/'.
            # Trim that down to just 'methodName'.
            try:
                last_namespace = demangled.rindex(':')
                demangled = demangled[last_namespace + 1:]
            except ValueError:
                # No ':' in string; nothing to do.
                pass

            name = demangled # Use demangled format for name.

        virtual = dieattr('virtuality', dwarf_constants.DW_VIRTUALITY_none)
        accessibility = dieattr('accessibility', dwarf_constants.DW_ACCESS_public)

        enclosing_class = context.get("class") or None

        origin = None
        if dieattr('abstract_origin'):
            origin = _resolve_abstract_origin()

        return_type = _lookup_type() or _VOID

        if dieattr('low_pc') is None:
            # abstract instance of the method. Just the method signature, or else the abstract
            # instance of an inline method.
            is_decl = True
            is_def = False
        else:
            is_decl = origin is not None # If it has no abstract origin, it's also the declaration.
            is_def = True # It has a PC range... concrete method definition.

        method = MethodInfo(name, return_type, cuns, enclosing_class, virtual, accessibility,
            is_decl, is_def, origin)

        if enclosing_class:
            enclosing_class.addMethod(method)
        else:
            # it's a standalone method in the CU
            cuns.addMethod(method)

        if dieattr('external') and not enclosing_class:
            # Also publish this method to the globals list in addition to the CUNS.
            _global_syms.addMethod(method)

        _add_entry(method, None, die.offset)

        if dieattr('low_pc'):
            # has a PC range associated with it.
            cuns.define_pc_range(dieattr('low_pc'), dieattr('high_pc'), method, name)

        frame_base_loc = _get_locations('frame_base')
        if frame_base_loc is not None:
            method.setFrameBase(frame_base_loc)

        ctxt = context.copy()
        ctxt['method'] = method
        for child in die.iter_children():
            parseTypesFromDIE(child, cuns, ctxt)
    elif die.tag == 'DW_TAG_inlined_subroutine':
        # Defines a PC range associated with a subroutine inlined within another one.
        definition = _resolve_abstract_origin()
        name = definition.method_name or dieattr('name') # try demangled name from def'n first
        return_type = definition.return_type or _lookup_type() or _VOID

        # inline instance of a method is niether declaration nor definition.
        is_decl = False
        is_def = False

        method = MethodInfo(name, return_type, cuns, definition.member_of, definition.virtual,
            definition.accessibility, is_decl, is_def, definition)

        if dieattr('low_pc') and dieattr('high_pc'):
            cuns.define_pc_range(dieattr('low_pc'), dieattr('high_pc'), method, definition.name)
        elif dieattr('ranges'):
            # Some inlined methods have a DW_AT_entry_pc and a 'DW_AT_ranges' field.
            # Use multiple PCRanges to record this.
            range_lists = context['range_lists']
            if range_lists:
                rangelist = range_lists.get_range_list_at_offset(dieattr('ranges'))
                for r in rangelist:
                    cuns.define_pc_range(r.begin_offset, r.end_offset, method, definition.name)

        frame_base_loc = _get_locations('frame_base')
        if frame_base_loc is not None:
            method.setFrameBase(frame_base_loc)

        _add_entry(method, None, die.offset)

        ctxt = context.copy()
        ctxt['method'] = method
        for child in die.iter_children():
            parseTypesFromDIE(child, cuns, ctxt)

    elif die.tag == 'DW_TAG_lexical_block':
        # Lexical block defines a PCRange that can contain variables.
        origin = None
        if dieattr('abstract_origin'):
            origin = _resolve_abstract_origin()
        lexical_scope = LexicalScope(origin, context['method'])
        _add_entry(lexical_scope, None, die.offset)
        if dieattr('low_pc') and dieattr('high_pc'):
            cuns.define_pc_range(dieattr('low_pc'), dieattr('high_pc'), lexical_scope, None)

        ctxt = context.copy()
        ctxt['method'] = lexical_scope
        for child in die.iter_children():
            parseTypesFromDIE(child, cuns, ctxt)
    elif die.tag == 'DW_TAG_subroutine_type':
        # Used only for 'pointers to methods'. Establishes a type for a pointer to
        # a method with a specified return type & formal arg types.
        # This is used as a target for a TAG_pointer_type to a vtable entry.
        name = dieattr('name')
        enclosing_class = context.get("class") or None
        return_type = _lookup_type() or _VOID
        method_type = MethodPtrType(name, return_type, enclosing_class)
        _add_entry(method_type, name, die.offset)
        ctxt = context.copy()
        ctxt['method'] = method_type
        for child in die.iter_children():
            parseTypesFromDIE(child, cuns, ctxt)
    elif die.tag == 'DW_TAG_formal_parameter':
        # type signature for a formal arg to a method.
        # artificial=1 if added by compiler (e.g., implicit 'this')
        # TODO(aaron): Should we actually add artificials to the type? Needed for stack dissection,
        # but needs to be suppressed for pretty-printing. (TODO - Add later)
        origin = None
        if dieattr('abstract_origin'):
            origin = _resolve_abstract_origin()
        name = dieattr('name')
        if name is None and origin is not None:
            name = origin.name
        base = _lookup_type()
        if base is None and origin is not None:
            base = origin.arg_type

        artificial = dieattr('artificial', 0)

        location = _get_locations()
        const_val = dieattr('const_value')

        #if location is not None and isinstance(location, list):
        #    print(f"Loading DIE {die.tag} {dieattr('name')} at offset {die.offset:x} (CU offset {cu_offset:x})")
        #    print(die)
        #    print(f"Location is {location}")

        formal = FormalArg(name, base, cuns, origin, location, const_val)
        _add_entry(formal, None, die.offset)
        if not artificial:
            context['method'].addFormal(formal)
    elif die.tag == 'DW_TAG_variable':
        origin = None
        if dieattr('abstract_origin'):
            origin = _resolve_abstract_origin()

        name = dieattr('name')
        if name is None and origin is not None:
            name = origin.var_name
        base = _lookup_type()
        if base is None and origin is not None:
            base = origin.var_type
        location = _get_locations()
        is_decl = dieattr('declaration') and True
        is_def = not is_decl # Variables are one or the other of decl and def.

        if context.get('method'):
            enclosing_scope = context['method']
        else:
            enclosing_scope = None

        if name is None:
            # Nothing to actually define here... degenerate variable entry.
            return

        var = VariableInfo(name, base, cuns, location, is_decl, is_def, origin, enclosing_scope)

        const_val = dieattr('const_value')
        if const_val is not None:
            # Hard-coded 'variable' value within this scope.
            var.setConstValue(const_val)

        if context.get('method'):
            # method or lexical block wrapped around this.
            context['method'].addVariable(var)
        else:
            # It's global in scope within the CU Namespace.
            cuns.addVariable(var)

        _add_entry(var, None, die.offset)

        if dieattr('external'):
            _global_syms.addVariable(var)
    else:
        # TODO(aaron): Consider parsing DW_TAG_GNU_call_site
        for child in die.iter_children():
            parseTypesFromDIE(child, cuns, context)



_default_context_keys = []

def parseTypeInfo(dwarf_info, debugger):
    int_size = debugger.get_arch_conf("int_size")
    _populateEncodings(int_size) # start with base primitive types.
    range_lists = dwarf_info.range_lists()

    context = {}
    context['debugger'] = debugger
    context['int_size'] = int_size
    context['range_lists'] = range_lists
    context['loc_lists'] = dwarf_info.location_lists()

    # TODO(aaron): Keep this list in sync with the initializers above and below.
    global _default_context_keys
    _default_context_keys = [ 'debugger', 'int_size', 'range_lists', 'loc_lists', 'dwarf_ver' ]

    for compile_unit in dwarf_info.iter_CUs():
        context['dwarf_ver'] = compile_unit.header['version']

        cuns = CompilationUnitNamespace(compile_unit.cu_offset, compile_unit, range_lists, debugger)
        _cu_namespaces.append(cuns)
        parseTypesFromDIE(compile_unit.get_top_DIE(), cuns, context)


# TODO(aaron): UnionType?
