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


class Variable(object):
  """Represents a generic global variable."""

  def __init__(self, arch, address, type_):
    self._arch = arch
    self._address = address
    self._type = type_

  def name(self):
    return NotImplementedError()

  def address(self):
    return self._address

  def type(self):
    return self._type

  def visit(self, program, is_definition):
    raise NotImplementedError()

  def is_declaration(self):
    raise NotImplementedError()

  def proto(self):
    proto = {}
    name = self.name()
    if len(name):
      proto["name"] = name
    proto["address"] = self.address()
    proto["type"] = self.type().proto(self._arch)
    return proto
