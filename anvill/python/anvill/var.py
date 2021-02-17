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

from abc import ABC, abstractmethod
from .type import Type


class Variable(object):
    """Represents a generic global variable."""

    __slots__ = ("_arch", "_address", "_type")

    def __init__(self, arch, address, type_):
        self._arch = arch
        self._address = address
        self._type = type_

    def address(self) -> int:
        return self._address

    def type(self) -> Type:
        return self._type

    # @abstractmethod
    def visit(self, program: "Program", is_definition: bool, add_refs_as_defs: bool):
        raise NotImplementedError()

    #  @abstractmethod
    def is_declaration(self):
        raise NotImplementedError()

    def proto(self):
        proto = {}
        proto["address"] = self.address()
        if self.type() != None:
            proto["type"] = self.type().proto(self._arch)

        return proto
