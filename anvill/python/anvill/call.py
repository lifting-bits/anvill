#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

from .arch import Arch
from .os import CC
from .type import Type, FunctionType, StructureType, VoidType
from .loc import Location
from typing import List, Dict, Any, Final, cast


class CallSite(object):
    """Represents a generic function."""

    __slots__ = (
        "_arch",
        "_func_address",
        "_address",
        "_parameters",
        "_return_values",
        "_cc",
        "_is_variadic",
        "_is_noreturn",
        "_call_stack_adjustment"
    )

    def __init__(
        self, arch: Arch, address: int, func_address: int,
        parameters: List[Location], return_values: List[Location],
        is_variadic: bool = False, is_noreturn: bool = False, cc: CC = 0,
        call_stack_adjustment: int = 0
    ):
        self._arch: Final[Arch] = arch
        self._address: Final[int] = address
        self._func_address: Final[int] = func_address
        self._parameters: Final[List[Location]] = parameters
        self._return_values: Final[List[Location]] = return_values
        self._is_variadic: Final[bool] = is_variadic
        self._is_noreturn: Final[bool] = is_noreturn
        self._cc: Final[CC] = cc
        self._call_stack_adjustment: Final[int] = call_stack_adjustment

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
        """Returns the call site address."""
        return self._address

    def function_address(self) -> int:
        """Return the address of the function containing this call site."""
        return self._func_address

    def calling_convention(self) -> CC:
        return self._cc

    def is_variadic(self) -> bool:
        return self._is_variadic

    def is_noreturn(self) -> bool:
        return self._is_noreturn

    def return_values(self) -> List[Location]:
        return self._return_values[:]

    def parameters(self) -> List[Location]:
        return self._parameters[:]

    def proto(self) -> Dict[str, Any]:
        return {
            "address": self._address,
            "function_address": self._func_address,
            "return_stack_pointer": self._arch.return_stack_pointer_proto(
                self._call_stack_adjustment),
            "is_variadic": self._is_variadic,
            "is_noreturn": self._is_noreturn,
            "calling_convention": cast(int, self._cc),
            "return_address": self._arch.return_address_proto(),
            "parameters": [loc.proto(self._arch) for loc in self._parameters],
            "return_values": [loc.proto(self._arch) for loc in self._return_values]
        }
