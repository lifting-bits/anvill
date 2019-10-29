# Copyright (c) 2019 Trail of Bits, Inc.
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

import weakref
import magic
import binaryninja as bn

from .arch import *
from .exc import *
from .function import *
from .loc import *
from .os import *
from .type import *

def _convert_binja_type(tinfo, cache):
  """Convert an Binja `Type` instance into a `Type` instance."""
  if tinfo in cache:
    return cache[tinfo]

  # Void type.
  if tinfo.type_class == bn.TypeClass.VoidTypeClass:
    return VoidType()

  # Pointer, array, or function.
  elif tinfo.type_class == bn.TypeClass.PointerTypeClass:
    ret = PointerType()
    cache[tinfo] = ret
    ret.set_element_type(_convert_binja_type(tinfo.element_type, cache))
    return ret

  elif tinfo.type_class == bn.TypeClass.FunctionTypeClass:
    ret = FunctionType()
    cache[tinfo] = ret
    ret.set_return_type(_convert_binja_type(tinfo.return_value, cache))
    
    index = 0
    for var in tinfo.parameters:
      ret.add_parameter_type(_convert_binja_type(var.type, cache))
      
    if tinfo.has_variable_arguments:
      ret.set_is_vararg()
      
    return ret

  elif tinfo.type_class == bn.TypeClass.ArrayTypeClass:
    ret = ArrayType()
    cache[tinfo] = ret
    ret.set_element_type(_convert_binja_type(tinfo.element_type, cache))
    ret.set_num_elements(tinfo.count)
    return ret

  elif tinfo.type_class == bn.TypeClass.StructureTypeClass:
    ret = StructureType()
    cache[tinfo] = ret
    return ret

  elif tinfo.type_class == bn.TypeClass.EnumerationTypeClass:
    ret = EnumType()
    cache[tinfo] = ret
    return ret

  elif tinfo.type_class == bn.TypeClass.BoolTypeClass:
    return BoolType()

  # long double ty may get represented as int80_t. If the size
  # of the IntegerTypeClass is [10, 12], create a float type
  # int32_t (int32_t arg1, int80_t arg2 @ st0)
  elif tinfo.type_class == bn.TypeClass.IntegerTypeClass:
    if tinfo.width in [1, 2, 4, 8, 16]:
      ret = IntegerType(tinfo.width, True)
      return ret
    elif tinfo.width in [10, 12]:
      width = tinfo.width
      return FloatingPointType(width)
  
  elif tinfo.type_class == bn.TypeClass.FloatTypeClass:
    width = tinfo.width
    return FloatingPointType(width)
      
  elif tinfo.type_class in [bn.TypeClass.VarArgsTypeClass,
                            bn.TypeClass.ValueTypeClass, 
                            bn.TypeClass.NamedTypeReferenceClass,
                            bn.TypeClass.WideCharTypeClass
                            ]:
    raise UnhandledTypeException(
      "Unhandled VarArgs, Value, or WideChar type: {}".format(str(tinfo)),
      tinfo)

  else:
    raise UnhandledTypeException(
        "Unhandled type: {}".format(str(tinfo)), tinfo)

def _get_calling_convention(bv, binja_func):
  cc = binja_func.calling_convention
  if cc.name == 'cdecl':
    return cc, bn.CallingConventionName.CdeclCallingConvention
  elif cc.name == '':
    pass
  pass

def get_type(ty):
  """Type class that gives access to type sizes, printings, etc."""
  
  if isinstance(ty, Type):
    return ty

  elif isinstance(ty, Function):
    return ty.type()

  elif isinstance(ty, bn.Type):
    return _convert_binja_type(ty, {})

  if not ty:
    return VoidType()

  raise UnhandledTypeException("Unrecognized type passed to `Type`.", ty)

def get_arch(bv):
  """Arch class that gives access to architecture-specific functionality."""
  name = bv.arch.name
  if name == "x86_64":
    return AMD64Arch()
  elif name == "x86":
    return X86Arch()
  elif name == "aarch64":
    return AArch64Arch()
  else:
    raise UnhandledArchitectureType(
        "Missing architecture object type for architecture '{}'".format(name))

def get_os(bv):
  """OS class that gives access to OS-specific functionality."""
  platform = str(bv.platform)
  if 'linux' in platform:
    return LinuxOS()
  elif "mac" in platform:
    return MacOS()
  elif "windows" in platform:
    return WindowsOS()
  else:
    raise UnhandledOSException(
        "Missing operating system object type for OS '{}'".format(platform))

class CallingConvention(object):
  def __init__(self, arch, bn_func):
    self._cc = bn_func.calling_convention
    self._arch = arch
    self._bn_func = bn_func
    self._int_arg_regs = self._cc.int_arg_regs
    self._float_arg_regs = self._cc.float_arg_regs
    if self._cc.name == 'cdecl':
      self._float_arg_regs = ['st0', 'st1', 'st2', 'st3', 'st4', 'st5']

  def is_sysv(self):
    return self._cc.name == 'sysv'

  def is_cdecl(self):
    return self._cc.name == 'cdecl'

  @property
  def next_int_arg_reg(self):
    try:
      reg_name = self._int_arg_regs[0]
      del self._int_arg_regs[0]
      return reg_name
    except:
      return 'invalid int register'

  @property
  def next_float_arg_reg(self):
    reg_name = self._float_arg_regs[0]
    del self._float_arg_regs[0]
    return reg_name
      
  @property
  def return_regs(self):
    for reg in self._bn_func.return_regs:
      yield reg


class BNFunction(Function):
  def __init__(self, arch, address, func_type, bn_func):
    super(BNFunction, self).__init__(arch, address, func_type)
    self._bn_func = bn_func

  def name(self):
    return self._bn_func.name

_FUNCTIONS = weakref.WeakValueDictionary()

def get_function(bv, arch, address):
  """Given an architecture and an address, return a `Function` instance or
  raise an `InvalidFunctionException` exception."""
  global _FUNCTIONS

  binja_func = bv.get_function_at(address)
  if not binja_func:
    func_contains = bv.get_functions_containing(address)
    if len(func_contains):
      binja_func = func_contains[0]

  if not binja_func:
    raise InvalidFunctionException(
      "No function defined at or containing address {:x}".format(address))

  print binja_func.name, binja_func.function_type
  func_type =  get_type(binja_func.function_type)
  calling_conv = CallingConvention(arch, binja_func)

  index = 0
  param_list = []
  for var in binja_func.parameter_vars:
    source_type = var.source_type
    var_type = var.type
    arg_type = get_type(var_type)

    if source_type == bn.VariableSourceType.RegisterVariableSourceType:
      if bn.TypeClass.IntegerTypeClass == var_type.type_class or \
        bn.TypeClass.PointerTypeClass == var_type.type_class:
        reg_name = calling_conv.next_int_arg_reg
      elif bn.TypeClass.FloatTypeClass == var_type.type_class:
        reg_name = calling_conv.next_float_arg_reg
      elif bn.TypeClass.VoidTypeClass == var_type.type_class:
        reg_name = 'invalid void'
      else:
        reg_name = None
        raise AnvillException("No variable type defined for function parameters")

      loc = Location()
      loc.set_register(reg_name)
      param_list.append(loc)

    elif source_type == bn.VariableSourceType.StackVariableSourceType:
      loc = Location()
      loc.set_memory(bv.arch.stack_pointer, var.storage)
      param_list.append(loc)

    index += 1

  ret_list = []
  retTy = get_type(binja_func.return_type)
  if not isinstance(retTy, VoidType):
    for reg in calling_conv.return_regs:
      loc = Location()
      loc.set_register(reg.upper())
      loc.set_type(retTy)
      ret_list.append(loc)

  func = BNFunction(arch, address, func_type, binja_func)
  func.set_parameters(param_list)
  func.set_return_values(ret_list)

  _FUNCTIONS[address] = func
  return func

def load_binary(path):
  file_type = magic.from_file(path)
  if 'ELF' in file_type:
    bv_type = bn.BinaryViewType['ELF']
  elif 'PE32' in file_type:
    bv_type = bn.BinaryViewType['PE']
  elif 'Mach-O' in file_type:
    bv_type = bn.BinaryViewType['Mach-O']
  else:
    bv_type = bn.BinaryViewType['Raw']

  print 'Loading binary in binja... ', path
  bv = bv_type.open(path)
  bv.add_analysis_option("linearsweep")
  bv.update_analysis_and_wait()
  return bv
