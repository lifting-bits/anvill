
import weakref
import pprint

from collections import defaultdict, OrderedDict
from collections import namedtuple

try:
  from elftools.dwarf.descriptions import describe_form_class
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

def is_subprogram(die):
  return 'DW_TAG_subprogram' == die.tag
  
def is_parameter(die):
  return 'DW_TAG_formal_parameter' == die.tag

DWType = namedtuple('DWType', ['name', 'size', 'offset'])

class DWVariable(object):
  """Represents the variables from dwarf info"""
  def __init__(self, name, size, type=None):
    self._name = name
    self._size = size
    self._type = type

  def __repr__(self):
    return "<{} {} {}>".format(self._name, self._size, self._type)

  @property
  def size(self):
    return self._size

class DWFunction(object):
  """Represents a generic function from dwarf info"""
  def __init__(self, name, address, parameters = None, return_values = None):
    self._name = name
    self._address = address
    self._parameters = parameters
    self._return_values = return_values
    
  def __repr__(self):
    return "<{} {:x} {}>".format(self._name, self._address, self._parameters)

class DWARFCore(object):
  """ DWARF core handler class"""
  
  _dw_types_cache =  OrderedDict()

  _dw_subprogram_cache = OrderedDict()
  
  _dw_global_var_cache = {}
  
  __offset_to_die = {}
  
  def __init__(self, in_file):
    f = open(in_file, 'rb')
    self._felf = ELFFile(f)
    self._arch = self._felf.get_machine_arch()
    self._dwarf_info = self._felf.get_dwarf_info()
    # build offset_to_die map for tag processings
    self._build_diemap()
    self._build_typemap()
    print "{}".format(pprint.pformat(DWARFCore._dw_types_cache))
    
    self._process_subprogram()
    print "{}".format(pprint.pformat(DWARFCore._dw_subprogram_cache))
    #pprint.pprint(DWARFCore._dw_subprogram_cache)

  @classmethod
  def _process_direct_types(cls, die):
    name = get_name(die)
    size = get_size(die)
    if die.offset not in cls._dw_types_cache:
      cls._dw_types_cache[die.offset] = DWType(name=name, size=size, offset=die.offset)

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
        cls._dw_types_cache[die.offset] = DWType(name=name, size=size, offset=base_offset)

      except KeyError:
        raise ParseException("_process_indirect_types: die offset {:x} is not in typemap".format(die.offset))

    else:
      # some of the indirect types can't be resolved to base type
      # Add them to the typemap with dummy value
      name = get_name(die)
      size = get_size(die)
      cls._dw_types_cache[die.offset] = DWType(name=name, size=size, offset=die.offset)

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

    cls._dw_types_cache[die.offset] = DWType(name=name, size=size, offset=base_offset)
    
  @classmethod
  def _process_array_types(cls, die):
    if has_type(die):
      offset = die.attributes['DW_AT_type'].value + die.cu.cu_offset
      if offset not in cls._dw_types_cache:
        type_die = cls.__offset_to_die[offset]
        cls._process_types(type_die)
          
      name = get_name(die)
      try:
        size = cls._dw_types_cache[offset].size
        base_offset = cls._dw_types_cache[offset].offset
        cls._dw_types_cache[die.offset] = DWType(name=name, size=size, offset=base_offset)

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
  
  def _build_diemap(self):
    for cu in self._dwarf_info.iter_CUs():
      for die in cu.iter_DIEs():
        DWARFCore.__offset_to_die[die.offset] = die

  def _process_dies(self, die, fn):
    fn(die)
    for child in die.iter_children():
      self._process_dies(child, fn)
 
  def _build_typemap(self):
    for cu in self._dwarf_info.iter_CUs():
      top = cu.get_top_DIE()
      self._process_dies(top, DWARFCore._process_types)
  
  def _get_type_die(self, die):
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
  
  def _process_subprogram_tag(self, die):
    """Process DIE with subprogram tag"""
    
    assert die.tag == 'DW_TAG_subprogram'
    attr_lowpc = getAttribute(die, 'DW_AT_low_pc')
    # lowpc may not be available for external function; Not handling
    if attr_lowpc is None:
      return
  
    attr_highpc = getAttribute(die, 'DW_AT_high_pc')
    func_addr = attr_lowpc.value
    func_name = get_name(die)
    
    func_params = []
    for child in die.iter_children():
      if is_parameter(child):
        dwtype = self._get_type_die(child)
        size = dwtype.size if dwtype is not None else 0
        func_params.append(DWVariable(get_name(child), size, dwtype))
        if hasAttribute(child, 'DW_AT_location'):
          attr = getAttribute(child, 'DW_AT_location')
          
    # Get the function return type
    func_type = self._get_type_die(die)
    DWARFCore._dw_subprogram_cache[func_addr] = DWFunction(func_name, func_addr, func_params, func_type)

  def _process_subprogram(self):
    for cu in self._dwarf_info.iter_CUs():
      for die in cu.iter_DIEs():
        if is_subprogram(die):
          self._process_subprogram_tag(die)
      