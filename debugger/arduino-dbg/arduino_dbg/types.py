# (c) Copyright 2022 Aaron Kimball
#
# Parse program data type info from DIEs in .debug_info.

from sortedcontainers import SortedList

_INT_ENCODING = 5

PUBLIC = 1
PROTECTED = 2
PRIVATE = 3

class PCRange(object):
    """
    An interval of $PC values associated with a method implementation.
    """
    def __init__(self, pc_lo, pc_hi, method_name):
        self.pc_lo = pc_lo
        self.pc_hi = pc_hi
        self.method_name = method_name

    def includes_pc(self, pc):
        return self.pc_lo <= pc and self.pc_hi >= pc

    def __repr__(self):
        s = f'[{self.pc_lo:x}..{self.pc_hi:x}]'
        if self._method_name:
            s += f': {self.method_name}'
        return s

    def __cmp__(self, other):
        if self == other:
            return 0
        elif not isinstance(other, PCRange):
            return 1 # Always greater than incomparable things.
        elif self.pc_lo < other.pc_lo:
            return -1
        elif self.pc_hi < other.pc_hi:
            return -1
        else:
            return 1


class CompilationUnitNamespace(object):
    """
        Compilation Unit-specific namespacing for types, methods, $PC ranges.
    """

    def __init__(self, die_offset, cu):
        self._named_types = {} # name -> type
        self._addr_types = {}  # DIE offset -> type
        self._pc_ranges = SortedList()

        self._die_offset = die_offset
        self._cu = cu

    def getCU(self):
        return self._cu

    def define_pc_range(self, pc_lo, pc_hi, method_name):
        self._pc_ranges.add(PCRange(pc_lo, pc_hi, method_name))

    def get_ranges_for_pc(self, pc):
        """
        Return all PCRanges in this CU that include $PC.
        Returned in sorted order.
        """
        out = SortedList()
        for pcr in self._pc_ranges:
            if pcr.includes_pc(pc):
                out.add(pcr)
            elif pcr.pc_lo > pc:
                # We've walked past anything relevant.
                break
        return out

    def add_type(self, typ, name, addr):
        if name and not self._named_types.get(name):
            self._named_types[name] = typ

        if addr:
            try:
                self._addr_types[addr]
                # Error: if we found an entry, we're trying to multiply-define it.
                raise Exception(f"Already defined type at addr {addr:x}")
            except KeyError:
                # Typical case: haven't yet bound this addr to a typedef. Do so here.
                self._addr_types[addr] = typ

    def type_by_name(self, name):
        return self._named_types.get(name) or None

    def type_by_addr(self, addr):
        return self._addr_types.get(addr) or None

    def has_addr_type(self, addr):
        return self.type_by_addr(addr) is not None

    def __repr__(self):
        return f'Compilation unit (@offset {self._die_offset:x})'

class PrgmType(object):
    """
    A datatype within the debugged program.
    """

    def __init__(self, name, size, parent_type=None):
        self.name = name
        self.size = size
        self._parent_type = parent_type


    def parent_type(self):
        """
        Return the type underlying this one, if any, or None otherwise.
        """
        return self._parent_type

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

class MethodType(PrgmType):
    def __init__(self, method_name, return_type, formal_args, member_of=None, virtual=0, accessibility=1):
        name = f'{return_type} '
        if member_of:
            name += f'{member_of.name}::'
        name += f'{method_name}()'
        PrgmType.__init__(self, name, 0, None)
        self.method_name = method_name
        self.return_type = return_type
        self.formal_args = formal_args.copy()
        self.member_of = member_of
        self.virtual = virtual
        self.accessibility = accessibility

    def addFormal(self, arg):
        if arg is None:
            arg = _VOID
        self.formal_args.append(arg)

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
        s += f'{self.return_type} {self.method_name}('
        s += ', '.join(map(lambda arg: f'{arg.name}', self.formal_args))
        s += ')'
        if self.virtual == 2:
            # pure virtual.
            s += ' = 0'
        return s

class FieldType(PrgmType):
    def __init__(self, field_name, member_of, field_type, offset, accessibility):
        PrgmType.__init__(self, f'{member_of.name}::{field_name} {field_type}', field_type.size, field_type)
        self.field_name = field_name
        self.member_of = member_of
        self.offset = offset
        self.accessibility = accessibility

    def __repr__(self):
        s = ''
        if self.accessibility == PUBLIC:
            s += 'public '
        elif self.accessibility == PROTECTED:
            s += 'protected '
        elif self.accessibility == PRIVATE:
            s += 'private '
        return f'{s}{self.parent_type().name} {self.field_name} [size={self.parent_type().size}, offset={self.offset:#x}]'

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

    def addField(self, field_type):
        self.fields.append(field_type)


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


_encodings = {} # Global encodings table (encodingId -> PrgmTypE)
_cu_namespaces = [] # Set of CompilationUnitNamespace objects.

def types():
    """
    Iterator over all typedefs.
    """
    for cuns in _cu_namespaces:
        for (name, typ) in cuns._named_types.items():
            yield (name, typ)

# TODO(aaron): Define 'types()' to iterate over all typedefs
# TODO(aaron): Define getTypeByName(name, pc) to get the type w/ a given name in the right pc range.
# TODO(aaron): Define getMethodsForPC(pc) to get the stack of inlined methods leading into PC.


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
        elif not cuns.has_addr_type(addr):
            # We haven't processed this address yet; it's e.g. a forward reference.
            # We need to process that entry before returning a type to the caller of this method.
            sub_die = cu.get_DIE_from_refaddr(addr)
            parseTypesFromDIE(sub_die, cuns, {})

        return cuns.type_by_addr(addr)

    def _add_type(typ, name, addr):
        cuns.add_type(typ, name, addr)

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


    if not die.tag:
        return # null DIE to terminate nested set.
    elif cuns.has_addr_type(die.offset):
        return # Our seek-driven parsing has already parsed this entry, don't double-process.

    total_off = die.offset + cu_offset
    print(f"Loading DIE {die.tag} {dieattr('name')} at offset {die.offset:x} (CU offset {cu_offset:x})")
    #print(die)

    if dieattr('name') and cuns.type_by_name(dieattr('name')):
        # We're redefining a type name that already exists.
        # Just copy the existing definition into this address.
        _add_type(cuns.type_by_name(dieattr('name')), None, die.offset)
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
            _add_type(prim, None, die.offset)
        elif size == prim.size:
            _add_type(AliasType(name, prim), name, die.offset)
        else:
            _add_type(PrimitiveType(name, size), name, die.offset)

    elif die.tag == 'DW_TAG_const_type':
        base = _lookup_type() or _VOID
        const = ConstType(base)
        _add_type(const, const.name, die.offset)
    elif die.tag == 'DW_TAG_volatile_type':
        # define 'volatile foo' as an alias to type foo.
        base = _lookup_type()
        _add_type(base, 'volatile ' + base.name, die.offset)
    elif die.tag == 'DW_TAG_pointer_type':
        base = _lookup_type() or _VOID
        ptr = PointerType(base)
        _add_type(ptr, ptr.name, die.offset)
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
        virtual = dieattr('virtuality', 0)
        accessibility = dieattr('accessibility', 1)

        enclosing_class = context.get("class") or None
        method = MethodType(name, _VOID, [], enclosing_class, virtual, accessibility)
        if enclosing_class:
            enclosing_class.addMethod(method)
        _add_type(method, None, die.offset)

        ctxt = context.copy()
        ctxt['method'] = method
        for child in die.iter_children():
            parseTypesFromDIE(child, cuns, ctxt)
    elif die.tag == 'DW_TAG_subroutine_type':
        # Seems used only for 'pointers to methods', but doesn't actually include any info.
        # This is used as a target for a TAG_pointer_type to a vtable entry.
        enclosing_class = context.get("class") or None
        return_type = _lookup_type() or _VOID
        method = MethodType(None, return_type, [], enclosing_class, 0, 1)
        if enclosing_class:
            enclosing_class.addMethod(method)
        _add_type(method, None, die.offset)

        ctxt = context.copy()
        ctxt['method'] = method
        for child in die.iter_children():
            parseTypesFromDIE(child, cuns, ctxt)
    elif die.tag == 'DW_TAG_formal_parameter':
        # type signature for a formal arg to a method.
        # artificial=1 if added by compiler (e.g., implicit 'this')
        # TODO(aaron): Should we actually add artificials to the type? Needed for stack dissection,
        # but needs to be suppressed for pretty-printing. (TODO - Add later)
        base = _lookup_type()
        artificial = dieattr('artificial', 0)
        if artificial:
            return # skip for now. It's an implicit 'this' pointer.

        context['method'].addFormal(base)
        _add_type(base, None, die.offset)
    elif die.tag == 'DW_TAG_typedef':
        # name, type
        base = _lookup_type()
        name = dieattr('name')
        _add_type(AliasType(name, base), name, die.offset)
    elif die.tag == 'DW_TAG_array_type':
        # type
        base = _lookup_type()
        arr = ArrayType(base)
        _add_type(arr, arr.name, die.offset) # TODO: if this causes redundancy problems, remove arr.name.
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
        _add_type(enum, enum.name, die.offset)
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
        print(die)
        name = dieattr('name')
        size = dieattr('byte_size')

        if name and cuns.type_by_name(name) is not None:
            # This is a redefinition of a type that already exists. Just install it here.
            # TODO: Do we need to recurse and handle the redundant 'member', vtbl_ptr, etc.s?
            _add_type(getType(name), None, die.offset)
            return

        parent_type_offset = dieattr("containing_type", None)
        if parent_type_offset is None:
            parent_type = None
        else:
            parent_type = _lookup_type("containing_type")
        class_type = ClassType(name, size, parent_type)
        _add_type(class_type, name, die.offset)
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
        offset = 0 # TODO(aaron): Parse data_member
        print(f"data member location: [{data_member_location}]")
        accessibility = dieattr('accessibility', 1)
        field = FieldType(name, context.get("class"), base, offset, accessibility)
        context['class'].addField(field)
        _add_type(field, None, die.offset)
    else:
        if die.has_children:
            print(f"Scanning DIE: {die.tag}")
        for child in die.iter_children():
            parseTypesFromDIE(child, cuns, context)



def parseTypeInfo(dwarf_info, int_size):
    _populateEncodings(int_size) # start with base primitive types.

    context = {}
    context['int_size'] = int_size
    for compile_unit in dwarf_info.iter_CUs():
        cuns = CompilationUnitNamespace(compile_unit.cu_offset, compile_unit)
        _cu_namespaces.append(cuns)
        parseTypesFromDIE(compile_unit.get_top_DIE(), cuns, context)


# TODO(aaron): UnionType?
