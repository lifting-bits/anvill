#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

from typing import Tuple, Optional, Iterator, Set, Union

import binaryninja as bn
from binaryninja import MediumLevelILInstruction as mlinst
from binaryninja import LowLevelILInstruction as llinst

from .bninstruction import *
from .table import *
from .xreftype import *

from ..arch import Arch
from ..loc import Location
from ..function import Function
from ..type import *


def should_ignore_register(bv, reg_name):
    _IGNORE_REGS_LIST = {"aarch64": ["XZR", "WZR"]}
    try:
        return reg_name.upper() in _IGNORE_REGS_LIST[bv.arch.name]
    except KeyError:
        return False


class BNFunction(Function):
    def __init__(
        self,
        bn_func_or_var: Union[bn.Function, bn.Variable],
        arch: Arch,
        address: int,
        param_list: List[Location],
        ret_list: List[Location],
        func_type: Type,
        is_entrypoint=False,
        is_external=False,
    ):
        super(BNFunction, self).__init__(arch, address, param_list, ret_list,
                                         func_type, is_entrypoint)
        self._bn_func: Optional[bn.Function] = None
        self._is_external: bool = is_external

        # initialize bn_func if the binja object is of type `Function`
        self._bn_func_or_var: Union[bn.Function, bn.Variable] = bn_func_or_var
        if isinstance(bn_func_or_var, bn.Function):
            self._bn_func = bn_func_or_var

    def name(self) -> str:
        return self._bn_func_or_var.name

    def is_external(self) -> bool:
        return self._is_external

    def is_noreturn(self) -> bool:
        if self._bn_func is not None:
            return not self._bn_func.can_return.value
        return False

    def visit(self, program, is_definition, add_refs_as_defs):
        if not is_definition:
            return

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
                register_information = self._extract_types(
                    program, inst.operands, inst)
                for reg_info in register_information:
                    if should_ignore_register(
                        program.bv, self._arch.register_name(reg_info[0])
                    ):
                        continue

                    loc = Location()
                    loc.set_register(self._arch.register_name(reg_info[0]))
                    loc.set_type(reg_info[1])
                    if reg_info[2] is not None:
                        # fill_bytes misses some references, catch what we can
                        ref_eas.add(reg_info[2])
                        # print(f"inst_addr: {hex(inst.address)}, reg_info[2]: {reg_info[2]}, ref_eas: {ref_eas}")
                        # assert reg_info[2] in ref_eas
                        # assert reg_info 1 is a pointer, then reg2 should be in ea
                        # loc.set_value(reg_info[2])
                    #loc.set_address(inst.address)
                    #self._register_info.append(loc)

        # There is a distinction between declaration and definition. If the
        # function is a declaration, then Anvill only needs to know its symbols
        # and prototypes if its a definition, then Anvill will perform analysis
        # of the function and produce information for the function.
        for ref_ea in ref_eas:
            # If ref_ea is an invalid address
            seg = program.bv.get_segment_at(ref_ea)
            if seg is None:
                continue
            program.try_add_referenced_entity(ref_ea, add_refs_as_defs)

    def _extract_types_mlil(
        self, program, item_or_list, initial_inst: mlinst
    ) -> Iterator[Tuple[str, Type, Optional[int]]]:
        """
        This function decomposes a list of MLIL instructions and variables into a list of tuples
        that associate registers with pointer information if it exists.
        """
        if isinstance(item_or_list, list):
            for item in item_or_list:
                yield from self._extract_types_mlil(program, item, initial_inst)
        elif isinstance(item_or_list, mlinst):
            yield from self._extract_types_mlil(program, item_or_list.operands,
                                                initial_inst)
        elif isinstance(item_or_list, bn.Variable):
            if item_or_list.type is None:
                return
            # Sometimes the backing storage is a `temp` register, and not a real
            # register. If so, ignore it.
            # The use of LLIL_REG_IS_TEMP is correct here, as there is no MLIL equivalent
            # and it seem to use the same underlying data
            if bn.LLIL_REG_IS_TEMP(item_or_list.storage):
                return
            # We only care about registers that represent pointers.
            if item_or_list.type.type_class == bn.TypeClass.PointerTypeClass:
                if (
                    item_or_list.source_type
                    == bn.VariableSourceType.RegisterVariableSourceType
                ):
                    reg_name = program.bv.arch.get_reg_name(
                        item_or_list.storage)
                    yield reg_name, program.type_cache.get(item_or_list.type), None

    def _extract_types(
        self, program, item_or_list, initial_inst: llinst
    ) -> Iterator[Tuple[str, Type, Optional[int]]]:
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
                    ):  # or
                        # possible_pointer.type == bn.function.RegisterValueType.ConstantValue:
                        # Is there a scenario where a register has a ConstantValue type thats used as a pointer?
                        val_type = _convert_bn_llil_type(
                            possible_pointer, item_or_list.info.size
                        )
                        yield item_or_list.name, val_type, possible_pointer.value

                except KeyError:
                    DEBUG(f"Unsupported register {item_or_list.name}")

                if initial_inst.mlil is not None:
                    yield from self._extract_types_mlil(
                        program, initial_inst.mlil, initial_inst.mlil
                    )

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
        mlil_inst = inst.mlil
        if mlil_inst is not None:
            _collect_xrefs_from_inst(bv, program, mlil_inst, ref_eas)


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
