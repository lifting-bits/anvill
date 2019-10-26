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


from .exc import *


class Type(object):
  def size(self, arch):
    raise NotImplementedError()

  def serialize(self, arch, ids):
    raise NotImplementedError()


class VoidType(Type):
  _INSTANCE = None
  
  def __new__(cls):
    if not cls._INSTANCE:
      cls._INSTANCE = super(VoidType, cls).__new__(cls)
    return cls._INSTANCE

  def serialize(self, arch, ids):
    return "v"

  def size(self, arch):
    raise UnhandledTypeException(
        "Void type has no size", self)


class PointerType(Type):
  def __init__(self):
    super(PointerType, self).__init__()
    self._elem_type = None

  def set_element_type(self, elem_type):
    assert isinstance(elem_type, Type)
    self._elem_type = elem_type

  def serialize(self, arch, ids):
    if not self._elem_type:
      return "*v"
    else:
      return "*{}".format(self._elem_type.serialize(arch, ids))


class SequentialType(Type):
  def __init__(self):
    super(SequentialType, self).__init__()
    self._elem_type = None
    self._num_elems = 1

  def set_element_type(self, elem_type):
    assert isinstance(elem_type, Type)
    self._elem_type = elem_type

  def set_num_elements(self, num):
    assert 0 < num
    self._num_elems = num

  def size(self, arch):
    elem_size = 1
    if self._elem_type:
      elem_size = self._elem_type.size(arch)
    return elem_size * self._num_elems


class ArrayType(SequentialType):
  def serialize(self, arch, ids):
    if not self._elem_type:
      return "[Bx{}]".format(self._num_elems)
    else:
      return "[{}x{}]".format(self._elem_type.serialize(arch, ids), self._num_elems)


class VectorType(SequentialType):
  def serialize(self, arch, ids):
    if not self._elem_type:
      return "<Bx{}>".format(self._num_elems)
    else:
      return "<{}x{}>".format(self._elem_type.serialize(arch, ids), self._num_elems)


class PaddingType(SequentialType):
  def __init__(self):
    super(PaddingType, self).__init__()
    self._num_elems = 1
    self._elem_type = IntegerType(1, False)

  def set_num_elements(self, size):
    assert 0 < size
    self._num_elems = size

  def serialize(self, arch, ids):
    return "[Bx{}]".format(self._num_elems)


class StructureType(Type):
  def __init__(self):
    super(StructureType, self).__init__()
    self._elem_types = []

  def add_element_type(self, elem_type):
    assert isinstance(elem_type, Type)
    self._elem_types.append(elem_type)

  def serialize(self, arch, ids):
    if self in ids:
      return "%{}".format(ids[self])

    tid = len(ids)
    ids[self] = tid
    elem_strs = []
    for elem_type in self._elem_types:
      elem_strs.append(elem_type.serialize(arch, ids))
    
    if not len(elem_strs):
      elem_strs.append("B")

    return "={}{{{}}}".format(tid, "".join(selem_strs))

  def size(self, arch):
    ret = 0
    for elem_type in self._elem_types:
      ret += elem_type.size(arch)
    
    if not ret:
      ret = 1  # To be addressable.
    
    return ret


class UnionType(Type):
  def __init__(self):
    super(UnionType, self).__init__()
    self._elem_types = []

  def add_element_type(self, elem_type):
    assert isinstance(elem_type, Type)
    self._elem_types.append(elem_type)

  def serialize(self, arch, ids):
    if self in ids:
      return "%{}".format(ids[self])

    tid = len(ids)
    ids[self] = tid

    max_size = 1
    max_str = "B"
    max_type = None

    for elem_type in self._elem_types:
      elem_size = elem_type.size(arch)
      if elem_size > max_size:
        max_type = elem_type

    if max_type:
      max_str = max_type.serialize(arch, ids)

    return "={}{{{}}}".format(tid, max_str)

  def size(self, arch):
    max_size = 1  # To be addressable.
    for elem_type in self._elem_types:
      elem_size = elem_type.size(arch)
      if elem_size > max_size:
        max_size = elem_size

    return max_size


class IntegerType(Type):
  
  _FORM = {
    (1, True): "b",
    (1, False): "B",

    (2, True): "h",
    (2, False): "H",

    (4, True): "i",
    (4, False): "I",

    (8, True): "l",
    (8, False): "L",

    (16, True): "o",
    (16, False): "O"
  }

  _CACHE = {}

  def __new__(cls, size, is_signed):
    key = (size, is_signed)
    if key in cls._CACHE:
      return cls._CACHE[key]

    if key not in cls._FORM:
      raise UnhandledTypeException(
        "Cannot handle {}-byte {} integer type".format(
            size, ["unsigned", "signed"][is_signed]), None)

    inst = super(IntegerType, cls).__new__(cls, size, is_signed)
    cls._CACHE[key] = inst
    return inst

  def __init__(self, size, is_signed):
    super(IntegerType, self).__init__()
    self._size = size
    self._is_signed = is_signed

  def serialize(self, arch, ids):
    return self._FORM[self._size, self._is_signed]

  def size(self, arch):
    return self._size

  def is_signed(self):
    return self.is_signed


class FloatingPointType(Type):

  _FORM = {
    2: "e",
    4: "f",
    8: "d",

    # Depending on the ABI, the size of a `long double` may be 10 bytes, or it
    # may be 12 bytes.
    10: "D",
    12: "D"
  }

  _CACHE = {}

  def __new__(cls, size):
    if size in cls._CACHE:
      return cls._CACHE[size]

    if size not in cls._FORM:
      raise UnhandledTypeException(
        "Cannot handle {}-byte floating point type".format(size), None)

    inst = super(FloatingPointType, cls).__new__(cls, size)
    cls._CACHE[size] = inst
    return inst

  def __init__(self, size):
    self._size = size

  def serialize(self, arch, ids):
    return self._FORM[self._size]

  def size(self, arch):
    return self._size


class FunctionType(Type):
  def __init__(self):
    super(FunctionType, self).__init__()
    self._return_type = VoidType()
    self._param_types = []
    self._is_var_arg = False

    # NOTE(pag): This excludes the return address
    self._num_bytes_popped_off_stack = 0

  def set_return_type(self, return_type):
    assert isinstance(return_type, Type)
    self._return_type = return_type

  def add_parameter_type(self, param_type):
    assert isinstance(param_type, Type)
    self._param_types.append(param_type)

  def set_is_vararg(self, is_var_arg=True):
    self._is_var_arg = is_var_arg

  def set_num_bytes_popped_off_stack(self, num_bytes_popped_off_stack):
    self._num_bytes_popped_off_stack = num_bytes_popped_off_stack

  def num_bytes_popped_off_stack(self):
    return self._num_bytes_popped_off_stack

  def serialize(self, arch, ids):
    parts = ["("]
    if not len(self._param_types):
      if self._is_var_arg:
        parts.append("&")
      else:
        parts.append("v")
    else:
      for param_type in self._param_types:
        parts.append(param_type.serialize(arch, ids))

      if self._is_var_arg:
        parts.append("&")

    parts.append(self._return_type.serialize(arch, ids))
    parts.append(")")
    return "".join(parts)


class AliasType(Type):
  def __init__(self):
    super(AliasType, self).__init__()
    self._underlying_type = IntegerType(4, True)

  def set_underlying_type(self, underlying_type):
    assert isinstance(underlying_type, Type)
    self._underlying_type = underlying_type

  def serialize(self, arch, ids):
    self._underlying_type.serialize(arch, ids)

  def size(self, arch):
    return self._underlying_type.size(arch)


class EnumType(AliasType):
  pass


class TypedefType(AliasType):
  pass


class BoolType(AliasType):

  _INSTANCE = None

  def __new__(cls):
    if not cls._INSTANCE:
      cls._INSTANCE = super(BoolType, cls).__new__(cls)

    return cls._INSTANCE

  def __init__(self):
    super(BoolType, self).__init__()
    self.set_underlying_type(IntegerType(1, False))

