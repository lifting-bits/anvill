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


class Function(object):
  """Represents a generic function."""

  def __init__(self, arch, address, func_type):
    self._arch = arch
    self._address = address
    self._type = func_type
    self._parameters = []
    self._return_values = []

  def name(self):
    return NotImplementedError()

  def address(self):
    return self._address

  def type(self):
    return self._type

  def fill_bytes(self, dict_of_bytes):
    raise NotImplementedError()

  def is_declaration(self):
    raise NotImplementedError()

  def proto(self, arch):
    proto = {}
    proto["name"] = self.name()
    proto["address"] = self.address()
    proto["return_address"] = arch.return_address_proto()
    proto["return_stack_pointer"] = arch.return_stack_pointer_proto(
        type().num_bytes_popped_off_stack())
    proto["parameters"] = []
    proto["return_values"] = []
    return proto
