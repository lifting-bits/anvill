#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

from abc import ABC, abstractmethod

from .arch import Arch
from .os import CC
from .type import Type, FunctionType, StructureType, VoidType
from .loc import Location
from typing import List, Dict, Any, Final, Optional, Tuple, cast


class Function(ABC):
    """Represents a generic function."""

    __slots__ = (
        "_arch",
        "_address",
        "_parameters",
        "_return_values",
        "_type",
        "_cc",
        "_is_entrypoint",
    )

    def __init__(
        self, arch: Arch, address: int, parameters: List[Location],
        return_values: List[Location], func_type: FunctionType, context_assignments: Dict[str,int] = {},
        is_entrypoint: bool = False, cc: CC = 0
    ):
        assert isinstance(func_type, FunctionType)
        self._arch: Final[Arch] = arch
        self._address: Final[int] = address
        self._parameters: Final[List[Location]] = parameters
        self._return_values: Final[List[Location]] = return_values
        self._type: Final[Optional[FunctionType]] = func_type
        self._cc: Final[CC] = cc
        self._is_entrypoint: Final[bool] = is_entrypoint
        self._context_assignments: Dict[Tuple[str, int]] = context_assignments

        for param in self._parameters:
            assert isinstance(param, Location)
            param_type: Type = param.type()
            assert isinstance(param_type, Type)
            assert not isinstance(param_type, VoidType)
            assert not isinstance(param_type, FunctionType)

        if len(self._return_values) == 1:
            ret_val = self._return_values[0]
            assert isinstance(ret_val, Location)
            ret_type = ret_val.type()
            assert isinstance(ret_type, Type)
            assert not isinstance(ret_type, VoidType)
            assert not isinstance(ret_type, FunctionType)

        elif len(self._return_values):
            str_type = StructureType()
            for ret_val in self._return_values:
                assert isinstance(ret_val, Location)
                ret_type = ret_val.type()
                assert isinstance(ret_type, Type)
                assert not isinstance(ret_type, VoidType)
                assert not isinstance(ret_type, FunctionType)
                str_type.add_element_type(ret_type)

    def address(self) -> int:
        return self._address

    def type(self) -> Optional[FunctionType]:
        return self._type

    def calling_convention(self) -> CC:
        return self._cc

    @abstractmethod
    def visit(self, program, is_definition: bool, add_refs_as_defs: bool):
        ...

    def is_variadic(self) -> bool:
        return self._type.is_variadic()

    def is_noreturn(self) -> bool:
        return False

    def is_external(self) -> bool:
        return False

    def return_values(self) -> List[Location]:
        return self._return_values[:]

    def parameters(self) -> List[Location]:
        return self._parameters[:]

    def proto(self) -> Dict[str, Any]:
        proto: Dict[str, Any] = {
            "address": self.address(),
            "return_stack_pointer": self._arch.return_stack_pointer_proto(
                self.type().num_bytes_popped_off_stack()),
            "is_variadic": self.is_variadic(),
            "is_noreturn": self.is_noreturn(),
            "calling_convention": cast(int, self._cc)
        }

        if len(self._context_assignments) > 0:
            proto["context_assignments"] = self._context_assignments

        if not self._is_entrypoint:
            proto["return_address"] = self._arch.return_address_proto()

        func_type = self.type()
        if len(self._parameters) or len(self._return_values):
            proto["parameters"] = [loc.proto(self._arch)
                                   for loc in self._parameters]
            proto["return_values"] = [
                loc.proto(self._arch) for loc in self._return_values
            ]
        else:
            proto["type"] = func_type.proto(self._arch)

        return proto
