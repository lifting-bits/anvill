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


class Location(object):
  """Represents the location of some value."""

  def __init__(self):
    self._register = None
    self._mem_base_register = None
    self._mem_offset = 0

  def set_register(self, reg_name):
    assert not self._register
    assert not self._mem_base_register
    self._register = reg_name

  def set_memory(self, base_reg_name, offset):
    assert not self._register
    assert not self._mem_base_register
    self._mem_base_register = base_reg_name
    self._mem_offset = offset

  def proto(self):
    if self._register:
      return {
        "register": self._register
      }
    elif self._mem_base_register:
      return {
        "memory": {
          "register": self._mem_base_register,
          "offset": self._mem_offset
        }
      }
    else:
      raise InvalidLocationException("Can't get prototype of empty location")

