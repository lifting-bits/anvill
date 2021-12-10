#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#
import traceback
from typing import Tuple, Optional, Iterator, Set, Union, cast

import binaryninja as bn
from binaryninja import MediumLevelILInstruction as mlinst
from binaryninja import LowLevelILInstruction as llinst

from .bninstruction import *
from .table import *
from .xreftype import *
from .typecache import to_bool, TypeCache

from ..call import CallSite
from ..program import Specification
from ..arch import Arch, Register
from ..loc import Location
from ..function import Function
from ..os import CC, DEFAULT_CC
from ..type import *


def should_ignore_register(bv, reg_name: Optional[Register]):
    _IGNORE_REGS_LIST = {"aarch64": ["XZR", "WZR"]}
    try:
        return reg_name.upper() in _IGNORE_REGS_LIST[bv.arch.name]
    except:
        return False


class BNExternalFunction(Function):
    def __init__(self, bn_sym: bn.Symbol, bn_var: bn.DataVariable,
                 arch: Arch, address: int, func_type: Type):
        super(BNExternalFunction, self).__init__(arch, address, [], [], func_type,
                                                 False)
        self._bn_sym: bn.Symbol = bn_sym
        self._bn_var: bn.DataVariable = bn_var

    def name(self) -> str:
        return self._bn_sym.name

    def is_external(self) -> bool:
        return True

    def is_noreturn(self) -> bool:
        ftype = cast(bn.FunctionType, self._bn_var.type)
        return not to_bool(ftype.can_return)

    def visit(self, program, is_definition, add_refs_as_defs):
        pass


class BNFunction(Function):
    def __init__(
        self,
        bn_func: bn.Function,
        arch: Arch,
        address: int,
        param_list: List[Location],
        ret_list: List[Location],
        func_type: FunctionType,
        is_entrypoint=False,
        is_external=False
    ):
        super(BNFunction, self).__init__(arch, address, param_list, ret_list,
                                         func_type, is_entrypoint=is_entrypoint)
        self._is_external: bool = is_external
        self._bn_func: bn.Function = bn_func

    def name(self) -> str:
        return self._bn_func.name

    def is_external(self) -> bool:
        return self._is_external

    def is_noreturn(self) -> bool:
        return not to_bool(self._bn_func.can_return)

    def _set_loc(self, loc: Location, arch: bn.Architecture,
                    v: bn.Variable, stack_offset: int):
        if v.source_type == bn.VariableSourceType.RegisterVariableSourceType:
            reg_id = cast(bn.RegisterIndex, v.storage)
            bn_reg_name = arch.get_reg_name(reg_id)
            reg_name = self._arch.register_name(bn_reg_name)
            if reg_name is None:
                raise InvalidLocationException(
                    f"Could not locate register {bn_reg_name} in architecture")
            loc.set_register(reg_name)
        elif v.source_type == bn.VariableSourceType.StackVariableSourceType:
            loc.set_memory(self._arch.stack_pointer_name(),
                           v.storage + stack_offset)
        else:
            raise InvalidLocationException(
                f"Unsupported variable type {v.source_type}: {v}")

    def _var_to_loc(self, v: bn.Variable, arch: bn.Architecture, tc: TypeCache,
                    stack_offset: int) -> Location:
        loc = Location()
        loc.set_type(tc.get(v.type))
        self._set_loc(loc, arch, v, stack_offset)
        return loc

    def _const_to_loc(self, p: bn.MediumLevelILConstBase,
                      arch: bn.Architecture, type: Type,
                      stack_offset: int) -> Location:
        ll: Optional[bn.LowLevelILInstruction] = p.llil
        if ll is None:
            llils: List[bn.LowLevelILInstruction] = p.llils
            if not len(llils):
                raise InvalidLocationException(
                    f"Could not create location for {p}:{p.__class__} at {p.address:08x}")
            else:
                ll = llils[-1]

        assert ll is not None

        loc = Location()
        loc.set_type(type)

        # Constant argument through a register.
        if isinstance(ll, bn.LowLevelILSetRegSsa):
            dest: bn.ILRegister = ll.dest.reg
            if dest.temp:
                raise InvalidLocationException(
                    f"Could not infer register location from temporary "
                    f"register {ll}:{ll.__class__}")

            bn_reg_name = dest.arch.get_reg_name(dest.index)
            reg_name = self._arch.register_name(bn_reg_name)
            if reg_name is None:
                raise InvalidLocationException(
                    f"Could not locate register {bn_reg_name} in "
                    f"architecture")
            loc.set_register(reg_name)
            return loc

        # Constant argument on the stack.
        elif isinstance(ll, bn.LowLevelILStoreSsa):
            dest: Optional[bn.MediumLevelILInstruction] = ll.mapped_medium_level_il
            if dest is not None:
                if isinstance(dest, bn.MediumLevelILVar):
                    v: bn.Variable = cast(bn.MediumLevelILVar, dest).src
                    self._set_loc(loc, arch, v, stack_offset)
                    return loc
                elif isinstance(dest, bn.MediumLevelILSetVar):
                    v: bn.Variable = cast(bn.MediumLevelILSetVar, dest).dest
                    self._set_loc(loc, arch, v, stack_offset)
                    return loc
                else:
                    raise InvalidLocationException(
                        f"Unsupported Mapped MLIL {dest.operation} for constant {p} at "
                        f"{p.address:08x}")

        raise InvalidLocationException(
            f"Unsupported LLIL {ll}:{ll.__class__} for constant {p} at {p.address:08x}")

    def _visit_mlil_call(self, call: bn.MediumLevelILCallBase,
                         spec: Specification, tc: TypeCache,
                         ref_eas: Set[int]):
        bv: bn.BinaryView = self._bn_func.view
        arch: bn.Architecture = self._bn_func.arch or bv.arch
        called_func_ea: Optional[int] = None
        if isinstance(call.dest, int):
            called_func_ea = call.dest
        elif isinstance(call.dest, bn.MediumLevelILConstPtr):
            called_func_ea = call.dest.constant
        elif isinstance(call.dest, bn.MediumLevelILConst):
            called_func_ea = call.dest.constant

        if called_func_ea is not None:
            ref_eas.add(called_func_ea)

        rets: List[Location] = []
        params: List[Location] = []
        stack_offset = self._bn_func.get_reg_value_at(
            call.address, arch.stack_pointer, arch)
        stack_adjust: int = abs(stack_offset.value)

        rap = self._arch.return_address_proto()
        if "memory" in rap:
            stack_adjust += arch.address_size

        if 0 < stack_offset.value:  # Stack grows up.
            stack_adjust = -stack_adjust

        for v in call.output:
            rets.append(self._var_to_loc(v, arch, tc, stack_adjust))

        # We can get the parameters as variables.
        if len(call.params) == len(call.vars_read):
            for v in call.vars_read:
                params.append(self._var_to_loc(v, arch, tc, stack_adjust))

        # We have to figure out the parameters from the MLIL, LLIL, and
        # Mapped MLIL. The big issue is often constants.
        else:
            for i, p in enumerate(call.params):
                if isinstance(p, bn.MediumLevelILVar):
                    v: bn.Variable = cast(bn.MediumLevelILVar, p).src
                    params.append(self._var_to_loc(v, arch, tc, stack_adjust))
                elif isinstance(p, bn.MediumLevelILSetVar):
                    v: bn.Variable = cast(bn.MediumLevelILSetVar, p).dest
                    params.append(self._var_to_loc(v, arch, tc, stack_adjust))
                elif isinstance(p, bn.MediumLevelILConstBase):
                    params.append(self._const_to_loc(p, arch, tc.get(p.expr_type), stack_adjust))
                elif isinstance(p, bn.MediumLevelILVarField):
                    # TODO(pag): This isn't quite right but close enough.
                    v: bn.Variable = cast(bn.MediumLevelILVarField, p).src
                    params.append(self._var_to_loc(v, arch, tc, stack_adjust))
                else:
                    raise InvalidLocationException(
                        f"Unsupported parameter {p}:{p.__class__} at index {i} of call at {call.address:08x}")

        is_variadic: bool = False
        is_noreturn: bool = False
        cc: CC = DEFAULT_CC
        called_func: Optional[Function] = None
        if called_func_ea is not None:
            spec.add_function_declaration(called_func_ea, False)
            called_func = spec.get_function(called_func_ea)

        if called_func is not None:
            if not len(rets):
                rets = called_func.return_values()
            is_variadic = called_func.is_variadic()
            is_noreturn = called_func.is_noreturn()
            cc = called_func.calling_convention()
        else:
            # TODO(pag): Find calling convention.
            pass

        DEBUG(f"Call at 0x{call.address:08x} params:{params} returns:{rets} is_variadic:{is_variadic} is_noreturn:{is_noreturn} cc:{cc}")
        cs = CallSite(self._arch, call.address, self._bn_func.start, params,
                      rets, is_variadic, is_noreturn, cc,
                      self._bn_func.get_call_stack_adjustment(call.address).value)
        spec._call_sites[cs.function_address(), cs.address()] = cs

    def _visit_calls(self, spec: Specification, tc: TypeCache, ref_eas: Set[int]):
        mlil_func: Optional[bn.MediumLevelILFunction] = None
        try:
            mlil_func = self._bn_func.mlil
        except:
            return

        for mlil_block in mlil_func:
            for mlil_inst_ in mlil_block:
                mlil_inst = cast(bn.MediumLevelILInstruction, mlil_inst_)
                if isinstance(mlil_inst_, bn.MediumLevelILCallBase):
                    try:
                        self._visit_mlil_call(mlil_inst, spec, tc, ref_eas)
                    except:
                        ERROR(traceback.format_exc())


    def visit(self, program_: 'Specification', is_definition, add_refs_as_defs):
        if not is_definition:
            return

        program = cast('BNSpecification', program_)

        # The lifter does not support thumb2 instruction set. If the function
        # is of arch type `thumb2` then don't visit them and fill the memory
        # bytes. These functions will be declared but not defined in the lifted
        # code
        if self._bn_func is None or self._bn_func.arch.name == "thumb2":
            return

        mem = program.memory

        ref_eas: Set[int] = set()
        ea = self._bn_func.start
        max_ea = self._bn_func.highest_address
        self._fill_bytes(program, mem, ea, max_ea, ref_eas)

        # Collect typed register info for this function
        for block in self._bn_func.llil:
            for inst in block:
                for ref_ea in self._extract_types(program, inst.operands, inst):
                    ref_eas.add(ref_ea)

        # Collect call site types.
        tc: TypeCache = program._type_cache
        self._visit_calls(program, tc, ref_eas)

        # There is a distinction between declaration and definition. If the
        # function is a declaration, then Anvill only needs to know its symbols
        # and prototypes if its a definition, then Anvill will perform analysis
        # of the function and produce information for the function.
        for ref_ea in ref_eas:
            # If ref_ea is an invalid address
            seg = program.bv.get_segment_at(ref_ea)
            if seg is not None:
                program.try_add_referenced_entity(ref_ea, add_refs_as_defs)

    def _extract_types(
        self, program, item_or_list, initial_inst: llinst
    ) -> Iterator[int]:
        """
        This function decomposes a list of LLIL instructions and associates
        registers with pointer values if they exist. If an MLIL instruction
        exists for the current instruction, it uses the MLIL to get more
        information about otherwise implicit operands and their types if
        available. (ex, a call instruction has rdi, rsi as operands in the
        MLIL, we should check if they have pointer information)
        """

        # `item_or_list` could be empty string, return early in such cases. The
        # unimplemented operand shows up as empty string.
        try:
            if not (item_or_list and str(item_or_list)):
                return
        except:
            return  # Tokenizing the LLIL can raise exceptions.

        if isinstance(item_or_list, list):
            for item in item_or_list:
                yield from self._extract_types(program, item, initial_inst)
        elif isinstance(item_or_list, llinst):
            yield from self._extract_types(program, item_or_list.operands,
                                           initial_inst)
        elif isinstance(item_or_list, bn.lowlevelil.ILRegister):
            # Check if the register is not temp. Need to check if the temp register is
            # associated to pointer?? Look into MLIL to get more information
            if (not bn.LLIL_REG_IS_TEMP(item_or_list.index)) and \
                item_or_list.name != "x87control" and \
                item_or_list.name != "x87status":
                try:
                    # For every register, is it a pointer?
                    possible_pointer: bn.function.RegisterValue = (
                        initial_inst.get_reg_value(item_or_list.name)
                    )
                    if (
                        possible_pointer.type
                        == bn.function.RegisterValueType.ConstantPointerValue
                        or possible_pointer.type
                        == bn.function.RegisterValueType.ExternalPointerValue
                    ):
                        if possible_pointer.value:
                            yield possible_pointer.value

                except KeyError:
                    pass

    def _fill_bytes(self, program, memory, start, end, ref_eas):
        br = bn.BinaryReader(program.bv)
        for bb in self._bn_func.basic_blocks:
            for ea in range(bb.start, bb.end):
                seg = program.bv.get_segment_at(ea)
                br.seek(ea)

                # NOTE(artem): This is a workaround for binary ninja's fake
                # .externs section, which is (correctly) mapped as
                # not readable, not writable, and not executable.
                # because it is a fictional creation of the disassembler.
                # When something is marked as not accessible at all,
                # assume it is readable and executable
                is_executable = seg.executable
                if seg.writable == seg.readable == False:
                    is_executable = True

                memory.map_byte(ea, br.read8(), seg.writable, is_executable)
                inst = self._bn_func.get_low_level_il_at(ea)
                if inst and not is_unimplemented(program.bv, inst):
                    _collect_xrefs_from_inst(
                        program.bv, program, inst, ref_eas)


def _convert_bn_llil_type(
    constant_val: bn.function.RegisterValue, reg_size_bytes: int
) -> Type:
    """Convert LLIL register type to Anvill type"""
    if constant_val.type == bn.function.RegisterValueType.ConstantPointerValue:
        ret = PointerType()
        return ret
    elif constant_val.type == bn.function.RegisterValueType.ConstantValue:
        ret = IntegerType(reg_size_bytes, True)
        return ret


def _collect_xrefs_from_inst(
    bv, program, item_or_list, ref_eas, reftype=XrefType.XREF_NONE
):
    """Recursively collect xrefs in a IL instructions"""

    if isinstance(item_or_list, list):
        for item in item_or_list:
            _collect_xrefs_from_inst(bv, program, item, ref_eas, reftype)

    # If the item is not IL instructions don't process it further
    inst = item_or_list
    if not (
        isinstance(inst, bn.LowLevelILInstruction)
        or isinstance(inst, bn.MediumLevelILInstruction)
    ):
        return

    if is_unimplemented(bv, inst) or is_undef(bv, inst):
        return

    if is_function_call(bv, inst):
        reftype = XrefType.XREF_CONTROL_FLOW

    elif is_jump(bv, inst) or is_jump_to(bv, inst):
        reftype = XrefType.XREF_CONTROL_FLOW
        jump_targets = get_jump_targets(bv, inst.address)
        for jump_ea, targets in jump_targets.items():
            if len(targets) != 0:
                program.set_control_flow_targets(jump_ea, targets, True)

    elif is_memory_inst(bv, inst) or is_unimplemented_mem(bv, inst):
        mem_il = inst.dest if is_store_inst(bv, inst) else inst.src

        if is_constant(bv, mem_il):
            reftype = XrefType.XREF_MEMORY
        else:
            reftype = XrefType.XREF_DISPLACEMENT

        _collect_xrefs_from_inst(bv, program, mem_il, ref_eas, reftype)

        for opnd in inst.operands:
            _collect_xrefs_from_inst(bv, program, opnd, ref_eas)

    elif is_constant_pointer(bv, inst):
        const_ea = inst.constant
        if is_code(bv, const_ea) and not XrefType.is_memory(bv, reftype):
            ref_eas.add(const_ea)
        elif is_data(bv, const_ea):
            ref_eas.add(const_ea)

    # Recursively look for the xrefs in operands
    for opnd in inst.operands:
        _collect_xrefs_from_inst(bv, program, opnd, ref_eas, reftype)

    if isinstance(inst, bn.LowLevelILInstruction):
        try:
            mlil_inst = inst.mlil
            if mlil_inst is not None:
                _collect_xrefs_from_inst(bv, program, mlil_inst, ref_eas)
        except:
            pass


def is_code(bv, addr):
    for sec in bv.get_sections_at(addr):
        if sec.start <= addr < sec.end:
            return sec.semantics == bn.SectionSemantics.ReadOnlyCodeSectionSemantics
    return False


def is_data(bv, addr):
    for sec in bv.get_sections_at(addr):
        if sec.start <= addr < sec.end:
            return (
                sec.semantics == bn.SectionSemantics.ReadOnlyDataSectionSemantics
                or sec.semantics == bn.SectionSemantics.ReadWriteDataSectionSemantics
            )
    return False
