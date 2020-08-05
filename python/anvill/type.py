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


from .exc import *


class Type(object):
  __slots__ = tuple()

  def size(self, arch):
    raise NotImplementedError()

  def proto(self, arch):
    return self.serialize(arch, {})

  def serialize(self, arch, ids):
    raise NotImplementedError()

  def flatten(self, arch, out_list):
    raise NotImplementedError()

  def extract(self, arch, offset, size):
    goal_size = size
    goal_offset = offset
    elem_types = []
    out_types = []
    max_size = self.size(arch)
    self.flatten(arch, elem_types)

    curr_offset = 0
    i = 0
    accumulate = False
    while curr_offset < offset:
      elem_type = elem_types[i]
      i += 1
      elem_size = elem_type.size(arch)
      elem_offset = curr_offset
      curr_offset += elem_size

      # We're not at our limit yet.
      if curr_offset < offset:
        if accumulate:
          elem_types.append(elem_type)
        continue

      # We're at our limit, either start including stuff, or stop.
      elif curr_offset == offset:
        if accumulate:
          elem_types.append(elem_type)
          break
        else:
          accumulate = True
          offset = offset + size
          size = -max_size

      # Need to break the type into two.
      elif isinstance(elem_type, IntegerType):
        if accumulate:
          out_types.append(IntegerType(
              offset - elem_offset,
              elem_type.is_signed()))
          break
        else:
          out_types.append(IntegerType(
              curr_offset - offset,
              elem_type.is_signed()))
          accumulate = True
          offset = offset + size
          size = -max_size

      # Unbreakable type, represent it as an array of bytes.
      else:
        arr_type = ArrayType()
        out_types.append(arr_type)
        arr_type.set_element_type(IntegerType(1, False))
        if accumulate:
          arr_type.set_num_elements(offset - elem_offset)
          break
        else:
          arr_type.set_num_elements(curr_offset - offset)
          accumulate = True
          offset = offset + size
          size = -max_size

    if not len(elem_types):
      raise UnhandledTypeException(
          "Unable to create extracted type of size {} from offset {} in type {} of size {}".format(
              goal_size, goal_offset, self.serialize(arch, {}), max_size))

    elif len(elem_types) == 1:
      ret_type = elem_types[0]

    else:
      ret_type = StructureType()
      for elem_type in elem_types:
        ret_type.add_element_type(elem_type)

    # If we had an error, then give up and just return an array type of the
    # right size.
    ret_size = ret_type.size(arch)

    if ret_size > goal_size:
      raise UnhandledTypeException(
          "Unable to create extracted type of size {} from offset {} in type {} of size {}".format(
              goal_size, goal_offset, self.serialize(arch, {}), max_size))

    # Pad the return type to be the correct size.
    if ret_size < goal_size:
      pad_type = PaddingType()
      pad_type.set_num_elements(goal_size - ret_size)

      # Pad it.
      if isinstance(ret_type, StructureType):
        ret_type.add_element_type(pad_type)
      else:
        str_type = StructureType()
        str_type.add_element_type(ret_type)
        str_type.add_element_type(pad_type)
        ret_type = str_type

    return ret_type



class VoidType(Type):
  _INSTANCE = None

  __slots__ = tuple()

  def __new__(cls):
    if not cls._INSTANCE:
      cls._INSTANCE = super(VoidType, cls).__new__(cls)
    return cls._INSTANCE

  def serialize(self, arch, ids):
    return "v"

  def size(self, arch):
    raise UnhandledTypeException(
        "Void type has no size", self)

  def flatten(self, arch, out_list):
    raise NotImplementedError("Cannot flatten a void type")


class PointerType(Type):

  __slots__ = ('_elem_type',)

  def __init__(self):
    super(PointerType, self).__init__()
    self._elem_type = None

  def size(self, arch):
    return arch.pointer_size()

  def set_element_type(self, elem_type):
    assert isinstance(elem_type, Type)
    self._elem_type = elem_type

  def serialize(self, arch, ids):
    if not self._elem_type:
      return "*v"
    else:
      assert isinstance(self._elem_type, Type)
      return "*{}".format(self._elem_type.serialize(arch, ids))

  def flatten(self, arch, out_list):
    out_list.append(self)


class SequentialType(Type):
  __slots__ = ('_elem_type', '_num_elems')

  def __init__(self):
    super(SequentialType, self).__init__()
    self._elem_type = IntegerType(1, False)
    self._num_elems = 1

  def set_element_type(self, elem_type):
    assert isinstance(elem_type, Type)
    self._elem_type = elem_type

  def set_num_elements(self, num):
    assert 0 < num
    self._num_elems = num

  def size(self, arch):
    return self._elem_type.size(arch) * self._num_elems

  def flatten(self, arch, out_list):
    i = 0
    while i < self._num_elems:
      self._elem_type.flatten(arch, out_list)
      i += 1


class ArrayType(SequentialType):
  __slots__ = tuple()

  def serialize(self, arch, ids):
    if not self._elem_type:
      return "[Bx{}]".format(self._num_elems)
    else:
      return "[{}x{}]".format(self._elem_type.serialize(arch, ids), self._num_elems)


class VectorType(SequentialType):
  __slots__ = tuple()

  def serialize(self, arch, ids):
    if not self._elem_type:
      return "<Bx{}>".format(self._num_elems)
    else:
      return "<{}x{}>".format(self._elem_type.serialize(arch, ids), self._num_elems)


class PaddingType(SequentialType):
  __slots__ = tuple()

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
  __slots__ = ('_elem_types',)

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

    return "={}{{{}}}".format(tid, "".join(elem_strs))

  def size(self, arch):
    ret = 0
    for elem_type in self._elem_types:
      ret += elem_type.size(arch)
    
    if not ret:
      ret = 1  # To be addressable.
    
    return ret

  def flatten(self, arch, out_list):
    for elem_type in self._elem_types:
      elem_type.flatten(arch, out_list)


class UnionType(Type):
  __slots__ = ('_elem_types',)

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
      if elem_size >= max_size:
        max_type = elem_type

    if max_type:
      max_str = max_type.serialize(arch, ids)

    return "={}{{{}}}".format(tid, max_str)

  def size(self, arch):
    max_size = 1  # To be addressable.
    for elem_type in self._elem_types:
      elem_size = elem_type.size(arch)
      if elem_size >= max_size:
        max_size = elem_size

    return max_size

  def flatten(self, arch, out_list):
    max_size = 1
    max_type = IntegerType(1, False)

    for elem_type in self._elem_types:
      elem_size = elem_type.size(arch)
      if elem_size >= max_size:
        max_type = elem_type

    max_type.flatten(arch, out_list)


class IntegerType(Type):
  
  __slots__ = ('_size', '_is_signed')

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
            size, ["unsigned", "signed"][int(is_signed)]), None)

    inst = super(IntegerType, cls).__new__(cls)
    cls._CACHE[key] = inst
    return inst

  def __init__(self, size, is_signed):
    super(IntegerType, self).__init__()
    self._size = size
    self._is_signed = is_signed

  def serialize(self, arch, ids):
    ret = self._FORM[self._size, self._is_signed]
    assert ret is not None
    return ret

  def size(self, arch):
    return self._size

  def is_signed(self):
    return self._is_signed

  def flatten(self, arch, out_list):
    out_list.append(self)


class FloatingPointType(Type):

  __slots__ = ('_size',)

  _FORM = {
    2: "e",
    4: "f",
    8: "d",

    # Depending on the ABI, the size of a `long double` may be 10 bytes, or it
    # may be 12 bytes.
    10: "D",
    12: "D",

    # Quad-precision floating point.
    16: "Q"
  }

  _CACHE = {}

  def __new__(cls, size):
    if size in cls._CACHE:
      return cls._CACHE[size]

    if size not in cls._FORM:
      raise UnhandledTypeException(
        "Cannot handle {}-byte floating point type".format(size), None)

    inst = super(FloatingPointType, cls).__new__(cls)
    cls._CACHE[size] = inst
    return inst

  def __init__(self, size):
    self._size = size

  def serialize(self, arch, ids):
    ret = self._FORM[self._size]
    assert ret is not None
    return ret

  def size(self, arch):
    return self._size

  def flatten(self, arch, out_list):
    out_list.append(self)


class FunctionType(Type):
  __slots__ = ('_return_type', '_param_types', '_is_variadic', '_num_bytes_popped_off_stack')

  def __init__(self):
    super(FunctionType, self).__init__()
    self._return_type = VoidType()
    self._param_types = []
    self._is_variadic = False

    # NOTE(pag): This excludes the return address
    self._num_bytes_popped_off_stack = 0

  def set_return_type(self, return_type):
    assert isinstance(return_type, Type)
    self._return_type = return_type

  def add_parameter_type(self, param_type):
    assert isinstance(param_type, Type)
    self._param_types.append(param_type)

  def parameter_type(self, index):
    return self._param_types[index]

  def is_variadic(self):
    return self._is_variadic

  def num_bytes_popped_off_stack(self):
    return self._num_bytes_popped_off_stack

  def set_is_variadic(self, is_variadic=True):
    self._is_variadic = is_variadic

  def set_num_bytes_popped_off_stack(self, num_bytes_popped_off_stack):
    self._num_bytes_popped_off_stack = num_bytes_popped_off_stack

  def num_bytes_popped_off_stack(self):
    return self._num_bytes_popped_off_stack

  def serialize(self, arch, ids):
    parts = ["("]
    if not len(self._param_types):
      if self._is_variadic:
        parts.append("&")
      else:
        parts.append("v")
    else:
      for param_type in self._param_types:
        parts.append(param_type.serialize(arch, ids))

      if self._is_variadic:
        parts.append("&")

    parts.append(self._return_type.serialize(arch, ids))
    parts.append(")")
    return "".join(parts)

  def flatten(self, arch, out_list):
    raise NotImplementedError("Cannot flatten a function type")


class AliasType(Type):
  def __init__(self):
    super(AliasType, self).__init__()
    self._underlying_type = IntegerType(4, True)

  def set_underlying_type(self, underlying_type):
    assert isinstance(underlying_type, Type)
    self._underlying_type = underlying_type

  def serialize(self, arch, ids):
    assert isinstance(self._underlying_type, Type)
    return self._underlying_type.serialize(arch, ids)

  def size(self, arch):
    return self._underlying_type.size(arch)

  def flatten(self, arch, out_list):
    self._underlying_type.flatten(arch, out_list)


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

