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
from typing import Optional, Any, Dict

from .exc import *
from .type import Type


class Location(object):
    """Represents the location of some value."""

    __slots__ = ('_register', '_mem_base_register', '_mem_offset',
                 '_name', '_type')

    def __init__(self):
        self._register: Optional['Register'] = None
        self._mem_base_register: Optional['Register'] = None
        self._mem_offset: Optional[int] = None
        self._name: Optional[str] = None
        self._type: Optional[Type] = None

    def set_register(self, reg_name: Optional['Register']):
        if reg_name is None:
            raise InvalidLocationException("Unable to set register location")
        else:
            assert self._register is None
            assert self._mem_offset is None
            assert self._mem_base_register is None
            self._register = reg_name

    def set_memory(self, base_reg_name: Optional['Register'], offset: int):
        if base_reg_name is None:
            raise InvalidLocationException("Unable to set base register location")
        else:
            assert self._register is None
            assert self._mem_offset is None
            assert self._mem_base_register is None
            self._mem_base_register = base_reg_name
            self._mem_offset = offset

    def set_absolute_memory(self, address: int):
        assert self._mem_offset is None
        self._mem_offset = address

    def set_name(self, name: Optional[str]):
        if name is not None and len(name):
            self._name = name

    def set_type(self, type_: Type):
        assert isinstance(type_, Type)
        self._type = type_

    def type(self) -> Optional[Type]:
        return self._type

    def proto(self, arch) -> Dict[str, Any]:
        ret: Dict[str, Any] = {}
        if self._register is not None:  # reg
            ret["register"] = self._register
        elif self._mem_base_register is not None:  # [base_reg + offset]
            ret["memory"] = {
                "register": self._mem_base_register,
                "offset": self._mem_offset,
            }
        elif self._mem_offset is not None:  # [offset]
            ret["memory"] = {
                "register": "MEMORY",
                "offset": self._mem_offset,
            }
        else:
            raise InvalidLocationException("Can't get prototype of empty location")

        if self._name is not None:
            ret["name"] = self._name

        if self._type is not None:
            ret["type"] = self._type.proto(arch)

        return ret
