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


from .type import Type, FunctionType, StructureType
from .loc import Location


class Function(object):
  """Represents a generic function."""

  def __init__(self, arch, address, parameters, return_values):
    self._arch = arch
    self._address = address
    self._parameters = parameters
    self._return_values = return_values
    self._type = FunctionType()

    for param in self._parameters:
      assert isinstance(param, Location)
      param_type = param.type()
      assert isinstance(param_type, Type)
      self._type.add_parameter_type(param_type)

    if len(self._return_values) == 1:
      ret_val = self._return_values[0]
      assert isinstance(ret_val, Location)
      ret_type = ret_val.type()
      assert isinstance(ret_type, Type)
      self._type.set_return_type(ret_type)

    elif len(self._return_values):
      str_type = StructureType()
      for ret_val in self._return_values:
        assert isinstance(ret_val, Location)
        ret_type = ret_val.type()
        assert isinstance(ret_type, Type)
        str_type.add_element_type(ret_type)
      self._type.set_return_type(str_type)

  def name(self):
    return NotImplementedError()

  def address(self):
    return self._address

  def type(self):
    return self._type

  def fill_bytes(self, memory):
    raise NotImplementedError()

  def is_declaration(self):
    raise NotImplementedError()

  def proto(self):
    proto = {}
    name = self.name()
    if len(name):
      proto["name"] = name
    proto["address"] = self.address()
    proto["return_address"] = self._arch.return_address_proto()
    proto["return_stack_pointer"] = self._arch.return_stack_pointer_proto(
        self.type().num_bytes_popped_off_stack())
    proto["parameters"] = [loc.proto(self._arch) for loc in self._parameters]
    proto["return_values"] = [loc.proto(self._arch) for loc in self._return_values]
    return proto
