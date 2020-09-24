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
from .type import Type


class Location(object):
    """Represents the location of some value."""

    def __init__(self):
        self._register = None
        self._mem_base_register = None
        self._mem_offset = 0
        self._name = None
        self._type = None

    def set_register(self, reg_name):
        assert not self._register
        assert not self._mem_base_register
        self._register = reg_name

    def set_memory(self, base_reg_name, offset):
        assert not self._register
        assert not self._mem_base_register
        self._mem_base_register = base_reg_name
        self._mem_offset = offset

    def set_name(self, name):
        if len(name):
            self._name = name

    def set_type(self, type_):
        assert isinstance(type_, Type)
        self._type = type_

    def type(self):
        return self._type

    def proto(self, arch):
        if self._register:
            ret = {"register": self._register}
        elif self._mem_base_register:
            ret = {
                "memory": {
                    "register": self._mem_base_register,
                    "offset": self._mem_offset,
                }
            }
        else:
            raise InvalidLocationException("Can't get prototype of empty location")

        if self._name is not None:
            ret["name"] = self._name

        if self._type is not None:
            ret["type"] = self._type.proto(arch)

        return ret
