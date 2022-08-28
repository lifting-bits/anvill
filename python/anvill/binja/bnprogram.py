#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

import binaryninja as bn
from typing import Optional, Final, Iterable

import struct

from .typecache import *
from .bnfunction import *
from .bninstruction import *
from .bnvariable import *

from .table import *

from ..program import Specification
from ..arch import *
from ..os import *
from ..imageparser import *
from ..util import *
from ..type import *


def _is_function_pointer(bn_var):
    var_tinfo = bn_var.type
    if (
        var_tinfo.type_class == bn.TypeClass.PointerTypeClass
        and var_tinfo.element_type.type_class == bn.TypeClass.FunctionTypeClass
    ):
        return True
    return False


class BNSpecification(Specification):
    def __init__(self, bv: bn.BinaryView, path: str):
        Specification.__init__(self, _get_arch(bv), _get_os(bv))
        self._path: Final[str] = path
        self._bv: Final[bn.BinaryView] = bv

        # If it's an ELF with type ET_EXEC (2) then handle the return address
        # of `_start` specially.
        self._is_ELF_exe: Final[bool] = "ELF" in str(
            bv.view_type) and bv.executable

        self._type_cache: Final[TypeCache] = TypeCache(self._arch, self._bv)

        try:
            self._init_func_thunk_ctrl_flow()
        except:
            WARN("Failed to initialize the control flow information for function thunks")

    @property
    def bv(self):
        return self._bv

    def get_context_assignments_for_addr(self, ea: int) -> Dict[str, int]:
        func = next(iter(self._bv.get_functions_containing(ea)),None)
        if func:
            return get_entry_assignments(func) 
        else:
            return {}

    @property
    def type_cache(self):
        return self._type_cache

    def _try_add_symbol(self, ea: int):
        sym: Optional[bn.Symbol] = self._bv.get_symbol_at(ea)
        if not sym:
            return

        self.add_symbol(ea, sym.full_name)

    def get_variable_impl(self, address: int) -> Variable:
        """Given an address, return a `Variable` instance, or
        raise an `InvalidVariableException` exception."""

        # `bn_var` can be None if the data variable is not created
        # for it. raise an exception with the address information
        bn_var: Optional[bn.DataVariable] = self._bv.get_data_var_at(address)
        if bn_var is None:
            bn_var = self._bv.get_previous_data_var_before(address)
            if bn_var is not None:
                if bn_var.address < address < (bn_var.address + len(bn_var)):
                    return self.get_variable_impl(bn_var.address)

            raise InvalidVariableException(
                "Missing BN data variable at {:x}".format(address)
            )

        self._try_add_symbol(address)
        var_type = self.type_cache.get(bn_var.type)

        # fall back onto an array of bytes type for variables
        # of an unknown (void) type.
        if isinstance(var_type, VoidType):
            var_type = ArrayType()
            var_type.set_num_elements(1)

        return BNVariable(bn_var, self._arch, address, var_type)

    def _get_function_parameters(self, bn_func: bn.Function) -> List[Location]:
        """Get the list of function parameters from the function type. If
        the function type is incorrect or violate the calling conv, return
        the empty list
        """
        param_list: List[Location] = []

        if not isinstance(bn_func, bn.Function):
            return param_list

        index = 0
        # calling_conv = CallingConvention(
        #     self._arch, bn_func, bn_func.calling_convention
        # )

        DEBUG(
            f"Looking at function parameters for {bn_func.name} with {len(bn_func.parameter_vars)} parameters."
        )

        for var in bn_func.parameter_vars:
            source_type: bn.VariableSourceType = var.source_type
            var_type: Optional[bn.Type] = var.type

            # Fails to recover var_type for some function which may fail at later stage
            # e.g: int32_t __dlmopen(int32_t arg1, int32_t @ r9, int32_t @ r11)
            if var_type is None:
                continue

            arg_type = self.type_cache.get(var_type)

            if source_type == bn.VariableSourceType.RegisterVariableSourceType:

                # For some functions binary ninja identifies the function type incorrectly. The
                # register allocation in such cases violate calling convention.
                #
                # https://github.com/Vector35/binaryninja-api/issues/2399
                # https://github.com/Vector35/binaryninja-api/issues/2400
                #
                # Identify the storage register and discard the parameter variable
                # if they does not follow calling convention
                # e.g: int32_t main(int32_t arg1, void* arg2, int128_t arg3 @ q1, int64_t arg4 @ q2)
                #
                storage_reg_name = self._bv.arch.get_reg_name(var.storage)
                # if not (
                #     storage_reg_name in calling_conv.int_arg_reg
                #     or storage_reg_name in calling_conv.float_arg_reg
                # ):
                #     raise InvalidParameterException(
                #         f"Invalid parameters for function at {bn_func.start:x}: {bn_func.name}. "
                #         f"The bad storage register was: {storage_reg_name}."
                #     )

                if isinstance(arg_type, VoidType):
                    raise InvalidParameterException(
                        f"Void type parameter for function at {bn_func.start:x}: {bn_func.name}"
                    )

                param_reg: Optional[Register] = self._arch.register_name(
                    storage_reg_name)
                if param_reg is None:
                    raise InvalidParameterException(
                        f"Unrecognized parameter register name {storage_reg_name} in {bn_func.start:x}: {bn_func.name}"
                    )

                loc = Location()
                loc.set_register(param_reg)
                loc.set_type(arg_type)
                param_list.append(loc)

            elif source_type == bn.VariableSourceType.StackVariableSourceType:
                loc = Location()
                loc.set_memory(
                    self._arch.stack_pointer_name(), var.storage)
                loc.set_type(arg_type)
                param_list.append(loc)

            index += 1

        return param_list

    def _get_function_from_bnfunction(self, ea: int, bn_func: bn.Function) \
            -> Function:
        """Convert a bn.Function into an anvill.Function."""
        func_type = self.type_cache.get(bn_func.function_type)
        if not isinstance(func_type, FunctionType):
            raise InvalidFunctionException(
                f"Function at {ea:x} does not have a function type")

        arch: Arch = self._arch

        # In ELF binaries, the `_start` function does not return.
        #
        # TODO(pag): This check probably triggers a false-positive on shared
        #            libraries.
        is_entrypoint = False
        try:
            is_entrypoint = self._is_ELF_exe and self._bv.entry_function == bn_func
        except:
            pass
        
        if is_entrypoint:
            DEBUG(f"Found entrypoint {ea:08x}")
        is_external = False
        bn_sym = self._bv.get_symbol_at(ea)
        if bn_sym is not None:
            if bn_sym.type == bn.SymbolType.ImportedFunctionSymbol or \
               bn_sym.type == bn.SymbolType.LibraryFunctionSymbol or \
               bn_sym.type == bn.SymbolType.ExternalSymbol:
                is_external = True

        # Figure out the set of used return registers.
        ret_type = self.type_cache.get(bn_func.return_type)
        rets: List[Location] = []
        params: List[Location] = []

        use_type = not isinstance(ret_type, VoidType)
        try:
            if not isinstance(ret_type, VoidType):
                ret_regs = [arch.register_name(r) for r in bn_func.return_regs]
                if 1 == len(ret_regs):
                    use_type = False
                    rl = Location()
                    rl.set_register(ret_regs[0])
                    rl.set_type(ret_type)
                    rets.append(rl)
        except:
            use_type = True

        try:
            params = self._get_function_parameters(bn_func)
        except InvalidParameterException:
            use_type = True

        # Binary Ninja isn't that great at telling us where specifically return
        # values are, i.e. a given structure value might be spread over multiple
        # places. Thus, if we don't have just one return register, or if we
        # have issues getting the parameter locations, then fall back on using
        # just the function type.
        if use_type:
            func = BNFunction(
                bn_func, arch, ea, [], [], func_type,
                is_entrypoint=is_entrypoint, is_external=is_external)
        else:
            func = BNFunction(
                bn_func, arch, ea, params, rets, func_type,
                is_entrypoint=is_entrypoint, is_external=is_external)

        assert func is not None

        DEBUG(
            f"Created a new function from address: [{func.name()}] at 0x"
            f"{func.address():x} "
        )
        return func

    def _get_function_from_extern_sym(self, ea: int, bn_sym: bn.Symbol,
                                      bn_var: bn.DataVariable) -> Function:
        """Given a `bn.ExternalSymbol` and a `bn.DataVariable` referencing
        the same object, and assuming the type is a `bn.FunctionType`, convert
        this into an `anvill.Function`."""
        return BNExternalFunction(bn_sym, bn_var, self._arch, ea,
                                  self._type_cache.get(bn_var.type))

    def get_function_impl(self, ea: int) -> Optional[Function]:
        """Given an architecture and an address, return a `Function` instance or
        raise an `InvalidFunctionException` exception."""

        # Try to get the function starting at `ea`.
        bn_func: Optional[bn.Function] = self._bv.get_function_at(ea)
        if bn_func is not None:
            return self._get_function_from_bnfunction(bn_func.start, bn_func)

        # Try to get any function containing `ea`.
        last_start = 0xffffffff
        for containing_bn_func in self._bv.get_functions_containing(ea):
            if containing_bn_func.start != last_start:
                try:
                    return self._get_function_from_bnfunction(
                        containing_bn_func.start, containing_bn_func)
                except:
                    last_start = containing_bn_func.start

        # Try to see if this is actually a variable/external with function type
        # that we should interpret as being a function.
        bn_sym: Optional[bn.Symbol] = cast(
            Optional[bn.Symbol], self._bv.get_symbol_at(ea))
        if bn_sym is not None:
            if bn_sym.type == bn.SymbolType.ExternalSymbol:
                bn_var: Optional[bn.DataVariable] = \
                    self._bv.get_data_var_at(ea)
                if bn_var is not None and isinstance(bn_var.type, bn.FunctionType):
                    return self._get_function_from_extern_sym(ea, bn_sym, bn_var)

            # This is basically a thunk in PE binaries, I think.
            elif bn_sym.type == bn.SymbolType.ImportedFunctionSymbol:
                pass  # TODO(pag): Handle me.

            elif bn_sym.type == bn.SymbolType.LibraryFunctionSymbol:
                pass  # TODO(pag): Handle me.

        return None

    def get_symbols_impl(self, address: int) -> Iterable[str]:
        for s in self._bv.get_symbols(address, 1):
            yield s.name

    @property
    def functions(self) -> Iterable[int]:
        for f in self._bv.functions:
            yield f.start

    @property
    def symbols(self) -> Iterable[Tuple[int, str]]:
        for s in self._bv.get_symbols():
            yield s.address, s.name

    def _is_call_site(self, func: bn.Function, ea: int) -> bool:
        inst_il = func.get_low_level_il_at(ea)
        if is_function_call(self._bv, inst_il):
            return True
        return False

    def _init_func_thunk_ctrl_flow(self):
        """Initializes the control flow redirections and targets
        using function thunks"""

        # We only support the ELF format for now
        if self._bv.view_type != "ELF":
            return

        # List the function thunks first
        input_file_path = self._bv.file.filename
        image_parser = create_elf_image_parser(input_file_path)
        function_thunk_list = image_parser.get_function_thunk_list()

        # Go through each function thunk and add the redirection and targets
        is_32_bit = image_parser.get_image_bitness() == 32

        reader = bn.BinaryReader(self._bv, bn.Endianness.LittleEndian)

        redirected_thunk_list = []
        for function_thunk in function_thunk_list:
            # Read the call destination
            reader.seek(function_thunk.start)
            redirection_dest = reader.read32() if is_32_bit else reader.read64()

            # Get the variable defined at the dest address
            func_location = self._bv.get_data_var_at(function_thunk.start)
            if not func_location:
                DEBUG(
                    f"anvill: No variable defined for {hex(function_thunk.start)}/{function_thunk.name}"
                )
                continue

            # We should only have one caller
            for caller in func_location.code_refs:
                # Get the function containing this address; we need it to determine
                # its start address
                for caller_function in self._bv.get_functions_containing(
                    caller.address
                ):

                    # check if the caller function name is same as the function thunk name and add
                    # redirection if it matches.
                    # TODO: It is possible that the caller function name does not exactly matches the
                    # thunk name. find such cases and add them here
                    #
                    # It is not preferred to have a loose check here. That will lead to adding redirection
                    # for the wrong functions.
                    #
                    if (
                        function_thunk.name == caller_function.name
                        or function_thunk.name == caller_function.name[1:]
                    ):
                        DEBUG(
                            "anvill: Redirecting the user {:x} of thunk {} at {:x} to {:x}".format(
                                caller_function.start,
                                function_thunk.name,
                                function_thunk.start,
                                redirection_dest,
                            )
                        )

                        self.add_control_flow_redirection(
                            caller_function.start, redirection_dest
                        )

                        redirected_thunk_list.append(function_thunk.name)

                    # The imported address symbol can be references from both the thunks
                    # and other functions if it does not uses PLT. Check if the caller
                    # address is one of the call or jump instruction
                    #    e.g:    call [atoi@GOT]
                    #            jmp  [atoi@GOT]
                    #

                    # if the caller address is a call site, set a control flow
                    # target for the address
                    if self._is_call_site(caller_function, caller.address):
                        self.set_control_flow_targets(
                            caller.address, [redirection_dest], True
                        )

                        DEBUG(
                            "anvill: Adding target list {:x} -> [{:x}, complete=True] for {}".format(
                                caller.address, redirection_dest, function_thunk.name
                            )
                        )

                        continue

                    jump_table = get_jump_targets(
                        self._bv, caller.address, function_thunk.start
                    )
                    for jump_addr, targets in jump_table.items():
                        if function_thunk.start in targets:
                            self.set_control_flow_targets(
                                jump_addr, [redirection_dest], True
                            )

                            DEBUG(
                                "anvill: Adding target list {:x} -> [{:x}, complete=True] for {}".format(
                                    jump_addr, redirection_dest, function_thunk.name
                                )
                            )

        # Now check whether we successfully redirected all thunks
        for function_thunk in function_thunk_list:
            if function_thunk.name not in redirected_thunk_list:
                if function_thunk.name == "__libc_start_main":
                    continue

                WARN(
                    f"anvill: Thunk {hex(function_thunk.start)} ({function_thunk.name}) could not be redirected"
                )


def _get_os(bv: bn.BinaryView) -> OS:
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
            "Missing architecture object type for architecture '{}'".format(
                name)
        )
