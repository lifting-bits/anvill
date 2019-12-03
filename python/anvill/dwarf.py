
import weakref
import pprint
import enum

from collections import defaultdict, OrderedDict
from collections import namedtuple

try:
  from elftools.dwarf.descriptions import (describe_DWARF_expr, set_global_machine_arch, describe_form_class)
  from elftools.elf.elffile import ELFFile
except ImportError:
  print "Install pyelf tools"

from .exc import *

BASE_TYPES = [
  'DW_TAG_base_type',
  'DW_TAG_structure_type',
  'DW_TAG_union_type',
  'DW_TAG_enumeration_type',
]

INDIRECT_TYPES = [
  'DW_TAG_typedef',
  'DW_TAG_const_type',
  'DW_TAG_volatile_type',
  'DW_TAG_restrict_type',
  'DW_TAG_subroutine_type',
]

POINTER_TYPES = {
  'DW_TAG_pointer_type' : '*',
}

ARRAY_TYPES = {
  'DW_TAG_array_type',
}

'''
    DIE attributes utilities 
'''

def hasAttribute(die, name):
  return name in die.attributes

def getAttribute(die, name):
  if hasAttribute(die, name):
    return die.attributes[name]

def has_type(die):
  return hasAttribute(die, 'DW_AT_type')
  
def has_name(die):
  return hasAttribute(die, 'DW_AT_name')

def get_name(die):
  if 'DW_AT_name' in die.attributes:
    return die.attributes['DW_AT_name'].value
  else:
    return 'UNKNOWN'

def get_size(die):
  if 'DW_AT_byte_size' in die.attributes:
    return die.attributes['DW_AT_byte_size'].value
  else:
    return -1

def get_type(die):
  if 'DW_AT_type' in die.attributes:
    return die.attributes['DW_AT_type'].value
  else:
    return None

def get_upper_bound(die):
  if 'DW_AT_upper_bound' in die.attributes:
    return die.attributes['DW_AT_upper_bound'].value
  else:
    return 0

def is_subprogram(die):
  return 'DW_TAG_subprogram' == die.tag
  
def is_parameter(die):
  return 'DW_TAG_formal_parameter' == die.tag
  
def is_variable(die):
  return 'DW_TAG_variable' == die.tag

#DWType = namedtuple('DWType', ['name', 'size', 'offset'])

class Types(enum.Enum):
  DW_BASE = 0
            
  #Composite types.
  DW_ARRAY = 1
  DW_ENUM = 2
  DW_FUNCTION = 3
  DW_STRUCTURE = 4
  DW_TYPEDEF = 5
  DW_UNION = 6
  DW_CLASS = 7

  #Modifier types.
  DW_CONSTANT = 8
  DW_PACKED = 9
  DW_POINTER = 10
  DW_RESTRICT = 11
  DW_VOLATILE = 12

class DwarfType(object):
  def __init__(self, die):
    self._die = die
    self._load_type(die)
    self._type = Types.DW_BASE
    
  def _load_type(self, die):
    self._name = get_name(die)
    self._offset = die.offset
    self._size = 0;

  @property
  def name(self):
    return self._name

  @property
  def size(self):
    return self._size

  @property
  def offset(self):
    return self._offset

class DwarfArrayType(DwarfType):
  def __init__(self, die):
    super(DwarfArrayType, self).__init__(die)
    self._type = Types.DW_ARRAY
    for child in die.iter_children():
      assert child.tag == 'DW_TAG_subrange_type'
      self._size = get_upper_bound(child) + 1
      #elf._elem_type = DWARFCore._get_type_die(child)
  
  @property   
  def size(self):
    return self._size * self._elem_type.size
    
class DwarfEnumType(DwarfType):
  def __init__(self, die):
    super(DwarfEnumType, self).__init__(die)
    self._type = Types.DW_ENUM
    
class DwarfStructType(DwarfType):
  def __init__(self, die):
    super(DwarfStructType, self).__init__(die)
    self._type = Types.DW_STRUCTURE

class DwarfUnionType(DwarfStructType):
  def __init__(self, die):
    super(DwarfUnionType, self).__init__(die)
    self._type = Types.DW_UNION

class DwarfClassType(DwarfStructType):
  def __init__(self, die):
    super(DwarfClassType, self).__init__(die) 
    self._type = Types.DW_CLASS

class DwarfTypedefType(DwarfType):
  def __init__(self, die):
    super(DwarfTypedefType, self).__init__(die)
    self._type = Types.DW_TYPEDEF

class DwarfFunctionType(DwarfType):
  def __init__(self, die):
    super(DwarfFunctionType, self).__init__(die)
    self._type = Types.DW_FUNCTION

class DwarfModifierType(DwarfType):
  def __init__(self, die):
    super(DwarfModifierType, self).__init__(die)

class DwarfConstType(DwarfModifierType):
  def __init__(self, die):
    super(DwarfConstType, self).__init__(die)
    self._type = Types.DW_CONSTANT

class DwarfVolatileType(DwarfModifierType):
  def __init__(self, die):
    super(DwarfVolatileType, self).__init__(die)
    self._type = Types.DW_VOLATILE

class DwarfPointerType(DwarfModifierType):
  def __init__(self, die):
    super(DwarfPointerType, self).__init__(die)
    self._type = Types.DW_POINTER

class DWVariable(object):
  """Represents the variables from dwarf info"""
  def __init__(self, die, is_global=None):
    assert die.tag == 'DW_TAG_variable'
    self._die = die
    self._is_global = is_global
    self._address = 0
    self._load_variable(die)

  def __repr__(self):
    return "<{} {} {}>".format(self._name, self._size, self._type)

  def _load_variable(self, die):
    """Load the dwarf variable properties from die"""
    self._name = get_name(die)
    self._type = DWARFCore._get_type_die(die)
    self._size = self._type.size
    
    #if 'DW_AT_location' in die.attributes:
    #  attr = die.attributes['DW_AT_location']
    #  if attr.form not in ('DW_FORM_data4', 'DW_FORM_data8', 'DW_FORM_sec_offset'):
    #    loc_expr = "{}".format(describe_DWARF_expr(attr.value, die.cu.structs)).split(':')
    #    if loc_expr[0][1:] == 'DW_OP_addr':
    #      memory_ref = int(loc_expr[1][:-1][1:], 16)
    #      self._address = memory_ref
    #      if memory_ref not in DWARFCore._dw_global_var_cache:
    #        DWARFCore._dw_global_var_cache[memory_ref] = DWVariable(name, size, type)

  @property     
  def address(self):
    return self._address

  @property
  def size(self):
    return self._size

class DWFunction(object):
  """Represents a generic function from dwarf info"""
  def __init__(self, die):
    self._die = die
    self._name = None
    self._address = 0x0
    self._bound = 0x0
    self._args = []
    self._func_type = None
    self._m_vars = []

  def load_function(self):
    """Load function attributes from die"""
    
    assert self._die.tag == 'DW_TAG_subprogram'
    self._name = get_name(self._die)
    
    # get address of the function
    attr_lowpc = getAttribute(self._die, 'DW_AT_low_pc')
    self._address = attr_lowpc.value
      
    attr_highpc = getAttribute(self._die, 'DW_AT_high_pc')
    self._bound = attr_highpc.value
    
    self._func_type = DWARFCore._get_type_die(self._die)
    
    for child in self._die.iter_children():
      if is_parameter(child):
        dwtype = self._get_type_die(child)
        size = dwtype.size if dwtype is not None else 0
        self._args.append(DWVariable(child))
        
      elif is_variable(child):
        dwtype = self._get_type_die(child)
        size = dwtype.size if dwtype is not None else 0
        self._m_vars.append(DWVariable(child))

  def __repr__(self):
    return "<{} {:x} {}>".format(self._name, self._address, self._parameters)

  @property
  def address(self):
    return self._address

  @property
  def name(self):
    return self._name

class DWCompileUnit(object):
  def __init__(self, die):
    self._die = die 

class DWARFCore(object):
  """ DWARF core handler class"""
  
  _dw_cu_cache = OrderedDict()

  _dw_types_cache =  OrderedDict()

  _dw_subprogram_cache = OrderedDict()
  
  _dw_global_var_cache = OrderedDict()
  
  __offset_to_die = OrderedDict()
  
  def __init__(self, in_file):
    f = open(in_file, 'rb')
    self._felf = ELFFile(f)
    self._arch = self._felf.get_machine_arch()
    self._dwarf_info = self._felf.get_dwarf_info()
    # build offset_to_die map for tag processings
    self._load_die()
    self._load_cus()
    self._load_types()    
    self._load_subprograms()
    self._load_globalvars()
    #print "{}".format(pprint.pformat(DWARFCore._dw_global_var_cache))
    #pprint.pprint(DWARFCore._dw_subprogram_cache)

  @classmethod
  def _process_direct_types(cls, die):
    name = get_name(die)
    size = get_size(die)
    if die.tag == 'DW_TAG_base_type':
      dw_type = DwarfType(die)
    elif die.tag == 'DW_TAG_structure_type':
      dw_type = DwarfStructType(die)
    elif die.tag == 'DW_TAG_union_type':
      dw_type = DwarfUnionType(die)
    elif die.tag == 'DW_TAG_enumeration_type':
      dw_type = DwarfEnumType(die)
    else:
      dw_type = DwarfType(die)
    
    if die.offset not in cls._dw_types_cache:
      cls._dw_types_cache[die.offset] = dw_type

  @classmethod
  def _process_indirect_types(cls, die):
    if has_type(die):
      offset = die.attributes['DW_AT_type'].value + die.cu.cu_offset
      if offset not in cls._dw_types_cache:
        type_die = cls.__offset_to_die[offset]
        cls._process_types(type_die)

      try:
        name = get_name(die) if has_name(die) else cls._dw_types_cache[offset].name
        size = cls._dw_types_cache[offset].size
        base_offset = cls._dw_types_cache[offset].offset
        cls._dw_types_cache[die.offset] = DwarfType(die)

      except KeyError:
        raise ParseException("_process_indirect_types: die offset {:x} is not in typemap".format(die.offset))

    else:
      # some of the indirect types can't be resolved to base type
      # Add them to the typemap with dummy value
      name = get_name(die)
      size = get_size(die)
      cls._dw_types_cache[die.offset] = DwarfType(die)

  @classmethod
  def _process_pointer_types(cls, die):
    if has_type(die):
      offset = die.attributes['DW_AT_type'].value + die.cu.cu_offset
      if offset not in cls._dw_types_cache:
        type_die = cls.__offset_to_die[offset]
        cls._process_types(type_die)

      name = (cls._dw_types_cache[offset].name if offset in cls._dw_types_cache else 'UNKNOWN') + "*"
      base_offset = cls._dw_types_cache[offset].offset if offset in cls._dw_types_cache else -1
      size = die.cu['address_size']
    else:
      name = "void*"
      base_offset = die.offset
      size = die.cu['address_size']

    cls._dw_types_cache[die.offset] = DwarfType(die)
    
  @classmethod
  def _process_array_types(cls, die):
    if has_type(die):
      offset = die.attributes['DW_AT_type'].value + die.cu.cu_offset
      if offset not in cls._dw_types_cache:
        type_die = cls.__offset_to_die[offset]
        cls._process_types(type_die)

      try:
        cls._dw_types_cache[die.offset] = DwarfArrayType(die)

      except KeyError:
        raise ParseException("_process_array_types: die offset {:x} is not in typemap".format(die.offset))

  @classmethod
  def _process_types(cls, die):
    if die.tag in BASE_TYPES:
      cls._process_direct_types(die)

    elif die.tag in INDIRECT_TYPES:
      cls._process_indirect_types(die)
    
    elif die.tag in POINTER_TYPES:
      cls._process_pointer_types(die)
    
    elif die.tag in ARRAY_TYPES:
      cls._process_array_types(die)
      
  @classmethod
  def _get_type_die(cls, die):
    attr_value = get_type(die)
    if attr_value is None:
      return None
    # Fast path - lookup the offset in typemap
    try:
      # compute the global offset in the TYPES_CACHE
      offset = attr_value + die.cu.cu_offset
      return DWARFCore._dw_types_cache[offset]

    except KeyError:
       raise ParseException("_get_type_die: DIE is not available in the typemap\n {}".format(die.offset))
  
  def _load_die(self):
    """Build die map with the offset"""
    for cu in self._dwarf_info.iter_CUs():
      for die in cu.iter_DIEs():
        DWARFCore.__offset_to_die[die.offset] = die
        
  def _load_cus(self):
    """Build die map with the offset"""
    for cu in self._dwarf_info.iter_CUs():
      top_die = cu.get_top_DIE()
      dwarf_cu = DWCompileUnit(top_die)
      DWARFCore._dw_cu_cache[cu.cu_offset] = dwarf_cu

  def _process_dies(self, die, fn):
    fn(die)
    for child in die.iter_children():
      self._process_dies(child, fn)
 
  def _load_types(self):
    for cu in self._dwarf_info.iter_CUs():
      top = cu.get_top_DIE()
      self._process_dies(top, DWARFCore._process_types)

  def _load_subprograms(self):
    for cu in self._dwarf_info.iter_CUs():
      for die in cu.iter_DIEs():
        if is_subprogram(die):
          func = DWFunction(die)
          DWARFCore._dw_subprogram_cache[func.address] = func

  def _load_globalvars(self):
    for cu in self._dwarf_info.iter_CUs():
      for die in cu.iter_DIEs():
        if die.tag != "DW_TAG_variable" or die.get_parent().tag != "DW_TAG_compile_unit":
          continue

        if not die.attributes.get("DW_AT_external"):
          gvar = DWVariable(die)
          DWARFCore._dw_global_var_cache[gvar.address] = gvar
