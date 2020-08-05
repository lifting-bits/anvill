# Copyright (c) 2020 Trail of Bits, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import pprint
import sys

from .exc import *
from .os import *
from .type import *

try:
  from elftools.dwarf.descriptions import (describe_DWARF_expr, set_global_machine_arch, describe_form_class)
  from .dwarf_type import *

except ImportError:
  print("pyelftools not installed (pip install pyelftools)!")


def _is_ELF_file(path):
  with open(path, 'rb') as f:
    magic_bytes = f.read(4)
    return magic_bytes[0] == '\x7f' and magic_bytes[1] == 'E' and \
           magic_bytes[2] == 'L' and magic_bytes[3] == 'F'
  return False


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
    self._dw_type = DWARFCache._get_type_die(die)
    self._size = self._dw_type.size()
    self._type = self._dw_type.type()
    
    if 'DW_AT_location' in die.attributes:
      attr = die.attributes['DW_AT_location']
      if attr.form not in ('DW_FORM_data4', 'DW_FORM_data8', 'DW_FORM_sec_offset'):
        loc_expr = "{}".format(describe_DWARF_expr(attr.value, die.cu.structs)).split(':')
        if loc_expr[0][1:] == 'DW_OP_addr':
          self._address = int(loc_expr[1][:-1][1:], 16)

  @property     
  def address(self):
    return self._address

  @property
  def size(self):
    return self._size

  @property
  def type(self):
    return self._type

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
    
    self._func_type = DWARFCache._get_type_die(self._die)
    
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
  def __init__(self, in_file):
    try:
      from elftools.elf.elffile import ELFFile

      if not _is_ELF_file(in_file):
        print("{} is not an ELF-format binary".format(in_file))
        self._dwarf_info = None
        return

      f = open(in_file, 'rb')
      self._felf = ELFFile(f)
      self._arch = self._felf.get_machine_arch()
      self._dwarf_info = self._felf.get_dwarf_info()
      if self._dwarf_info is None:
        return
    
      # Load DIE to the die cache
      for cu in self._dwarf_info.iter_CUs():
        top_die = cu.get_top_DIE()
        DWARFCache._dw_cu_cache[cu.cu_offset] = DWCompileUnit(top_die)
        for die in cu.iter_DIEs():
          DWARFCache._offset_to_die[die.offset] = die

      self._load_types()
      self._load_subprograms()
      self._load_globalvars()
    except ImportError:
      pass

  # Process DIE to get the information
  def _process_dies(self, die, fn):
    fn(die)
    for child in die.iter_children():
      self._process_dies(child, fn)
 
  def _load_types(self):
    for cu in self._dwarf_info.iter_CUs():
      top = cu.get_top_DIE()
      self._process_dies(top, DWARFCache._process_types)

  def _load_subprograms(self):
    for cu in self._dwarf_info.iter_CUs():
      for die in cu.iter_DIEs():
        if is_subprogram(die):
          func = DWFunction(die)
          DWARFCache._dw_subprogram_cache[func.address] = func

  def _load_globalvars(self):
    for cu in self._dwarf_info.iter_CUs():
      for die in cu.iter_DIEs():
        if die.tag != "DW_TAG_variable" or die.get_parent().tag != "DW_TAG_compile_unit":
          continue

        if not die.attributes.get("DW_AT_external"):
          gvar = DWVariable(die)
          DWARFCache._dw_global_var_cache[gvar.address] = gvar

  def get_function(self, address):
    """ Get the dwarf function for an address
    """
    try:
      return DWARFCache._dw_subprogram_cache[address]
    except KeyError:
      return None

  def get_global_variable(self, address):
    """ Get the dwarf global variable for an address
    """
    try:
      return DWARFCache._dw_global_var_cache[address]
    except KeyError:
      return None
