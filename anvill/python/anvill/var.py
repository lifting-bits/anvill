#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

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

    @abstractmethod
    def visit(self, program: "Program", is_definition: bool, add_refs_as_defs: bool):
        ...

    def proto(self):
        proto = {}
        proto["address"] = self.address()
        if self.type() != None:
            proto["type"] = self.type().proto(self._arch)

        return proto
