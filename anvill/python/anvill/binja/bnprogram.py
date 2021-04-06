# Copyright (c) 2020-present Trail of Bits, Inc.
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


import binaryninja as bn


from .typecache import *
from .bnfunction import *
from .bnvariable import *


from anvill.program import *
from anvill.arch import *
from anvill.os import *


class BNProgram(Program):
    def __init__(self, bv: bn.BinaryView, path: str):
        Program.__init__(self, _get_arch(bv), _get_os(bv))
        self._path: Final[str] = path
        self._bv: Final[bn.BinaryView] = bv
        self._type_cache: Final[TypeCache] = TypeCache(self._bv)

    @property
    def bv(self):
        return self._bv

    @property
    def type_cache(self):
        return self._type_cache

    def get_variable_impl(self, address):
        """Given an address, return a `Variable` instance, or
        raise an `InvalidVariableException` exception."""

        # raise exception if the variable has invalid address
        seg = self._bv.get_segment_at(address)
        if seg is None:
            raise InvalidVariableException("Invalid variable address")

        arch = self._arch
        bn_var = self._bv.get_data_var_at(address)

        # `bn_var` can be None if the data variable is not created
        # for it. raise an exception with the address information
        if bn_var is None:
            raise InvalidVariableException(
                "Missing BN data variable at {:x}".format(address)
            )

        var_type = self.type_cache.get(bn_var.type)

        # fall back onto an array of bytes type for variables
        # of an unknown (void) type.
        if isinstance(var_type, VoidType):
            var_type = ArrayType()
            var_type.set_num_elements(1)

        return BNVariable(bn_var, arch, address, var_type)

    def get_function_impl(self, address):
        """Given an architecture and an address, return a `Function` instance or
        raise an `InvalidFunctionException` exception."""
        arch = self._arch

        bn_func = self._bv.get_function_at(address)
        if not bn_func:
            func_contains = self._bv.get_functions_containing(address)
            if func_contains and len(func_contains):
                bn_func = func_contains[0]

        if not bn_func:
            raise InvalidFunctionException(
                "No function defined at or containing address {:x}".format(address)
            )

        func_type = self.type_cache.get(bn_func.function_type)
        calling_conv = CallingConvention(arch, bn_func)

        index = 0
        param_list = []
        for var in bn_func.parameter_vars:
            source_type = var.source_type
            var_type = var.type

            # Fails to recover var_type for some function which may fail at later stage
            # e.g: int32_t __dlmopen(int32_t arg1, int32_t @ r9, int32_t @ r11)
            if var_type is None:
                continue

            arg_type = self.type_cache.get(var_type)

            if source_type == bn.VariableSourceType.RegisterVariableSourceType:
                if (
                    bn.TypeClass.IntegerTypeClass == var_type.type_class
                    or bn.TypeClass.PointerTypeClass == var_type.type_class
                ):
                    reg_name = calling_conv.next_int_arg_reg
                elif bn.TypeClass.FloatTypeClass == var_type.type_class:
                    reg_name = calling_conv.next_float_arg_reg
                elif bn.TypeClass.NamedTypeReferenceClass == var_type.type_class:
                    # The function paramater could be named alias of a float type.
                    # TODO(akshayk) Should check the underlying types as well for aliases??
                    if isinstance(arg_type, FloatingPointType):
                        reg_name = calling_conv.next_float_arg_reg
                    else:
                        reg_name = calling_conv.next_int_arg_reg
                elif bn.TypeClass.VoidTypeClass == var_type.type_class:
                    reg_name = "invalid void"
                else:
                    reg_name = None
                    raise AnvillException(
                        "No variable type defined for function parameters"
                    )

                loc = Location()
                loc.set_register(reg_name.upper())
                loc.set_type(arg_type)
                param_list.append(loc)

            elif source_type == bn.VariableSourceType.StackVariableSourceType:
                loc = Location()
                loc.set_memory(self._bv.arch.stack_pointer.upper(), var.storage)
                loc.set_type(arg_type)
                param_list.append(loc)

            index += 1

        ret_list = []
        retTy = self.type_cache.get(bn_func.return_type)
        if not isinstance(retTy, VoidType):
            for reg in calling_conv.return_regs:
                loc = Location()
                loc.set_register(reg.upper())
                loc.set_type(retTy)
                ret_list.append(loc)

        func = BNFunction(bn_func, arch, address, param_list, ret_list, func_type)
        return func

    def get_symbols_impl(self, address):
        for s in self._bv.get_symbols(address, 1):
            yield s.name

    @property
    def functions(self):
        for f in self._bv.functions:
            yield f.start

    @property
    def symbols(self):
        for s in self._bv.get_symbols():
            yield (s.address, s.name)


def _get_os(bv):
    """OS class that gives access to OS-specific functionality."""
    platform = str(bv.platform)
    if "linux" in platform:
        return LinuxOS()
    elif "mac" in platform:
        return MacOS()
    elif "windows" in platform:
        return WindowsOS()
    else:
        raise UnhandledOSException(
            "Missing operating system object type for OS '{}'".format(platform)
        )


def _get_arch(bv):
    """Arch class that gives access to architecture-specific functionality."""
    name = bv.arch.name
    if name == "x86_64":
        return AMD64Arch()
    elif name == "x86":
        return X86Arch()
    elif name == "aarch64":
        return AArch64Arch()
    elif name == "armv7":
        return AArch32Arch()
    elif name == "thumb2":
        return AArch32Arch()
    else:
        raise UnhandledArchitectureType(
            "Missing architecture object type for architecture '{}'".format(name)
        )
