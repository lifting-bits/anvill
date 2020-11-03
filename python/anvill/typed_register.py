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
from typing import Optional


class TypedRegister(object):
    """Represents a generic register."""
    __slots__ = ("_address", "_reg_name", "_reg_type", "_value")

    def __init__(self, address: int, reg_name: str, reg_type, value: Optional[int]):
        self._address = address
        self._value = value
        self._reg_name = reg_name
        self._reg_type = reg_type

    def address(self) -> int:
        return self._address

    # FIXME typehints
    def type(self):
        return self._reg_type

    def name(self) -> str:
        return self._reg_name

    def value(self) -> Optional[int]:
        return self._value

    def proto(self, arch):
        proto = {"address": self.address(), "register": self.name(), "type": self.type().proto(arch)}
        val = self.value()
        if val is not None:
            proto["value"] = val
        return proto
