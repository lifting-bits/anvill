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


from typing import Tuple, Optional


import binaryninja as bn
from binaryninja import MediumLevelILInstruction as mlinst
from binaryninja import LowLevelILInstruction as llinst


from .xreftype import *


from anvill.function import *
from anvill.type import *


class BNFunction(Function):
    def __init__(self, bn_func, arch, address, param_list, ret_list, func_type):
        super(BNFunction, self).__init__(arch, address, param_list, ret_list, func_type)
        self._bn_func = bn_func

    def name(self):
        return self._bn_func.name

    def visit(self, program, is_definition, add_refs_as_defs):
        if not is_definition:
            return

        mem = program.memory

        ref_eas: Set[int] = set()
        ea = self._bn_func.start
        max_ea = self._bn_func.highest_address
        self._fill_bytes(program, mem, ea, max_ea, ref_eas)

        # Collect typed register info for this function
        for block in self._bn_func.llil:
            for inst in block:
                register_information = self._extract_types(program, inst.operands, inst)
                for reg_info in register_information:
                    loc = Location()
                    loc.set_register(reg_info[0].upper())
                    loc.set_type(reg_info[1])
                    if reg_info[2] is not None:
                        # fill_bytes misses some references, catch what we can
                        ref_eas.add(reg_info[2])
                        # print(f"inst_addr: {hex(inst.address)}, reg_info[2]: {reg_info[2]}, ref_eas: {ref_eas}")
                        # assert reg_info[2] in ref_eas
                        # assert reg_info 1 is a pointer, then reg2 should be in ea
                        loc.set_value(reg_info[2])
                    loc.set_address(inst.address)
                    self._register_info.append(loc)
        # ea = effective_address
        # there is a distinction between declaration and definition
        # if the function is a declaration, then Anvill only needs to know its symbols and prototypes
        # if its a definition, then Anvill will perform analysis of the function and produce information for the func
        for ref_ea in ref_eas:
            # If ref_ea is an invalid address
            seg = program.bv.get_segment_at(ref_ea)
            if seg is None:
                continue
            program.try_add_referenced_entity(ref_ea, add_refs_as_defs)

    def _extract_types_mlil(
        self, program, item_or_list, initial_inst: mlinst
    ) -> List[Tuple[str, Type, Optional[int]]]:
        """
        This function decomposes a list of MLIL instructions and variables into a list of tuples
        that associate registers with pointer information if it exists.
        """
        results = []
        if isinstance(item_or_list, list):
            for item in item_or_list:
                results.extend(self._extract_types_mlil(program, item, initial_inst))
        elif isinstance(item_or_list, mlinst):
            results.extend(
                self._extract_types_mlil(program, item_or_list.operands, initial_inst)
            )
        elif isinstance(item_or_list, bn.Variable):
            if item_or_list.type is None:
                return results
            # Sometimes the backing storage is a `temp` register, and not a real
            # register. If so, ignore it.
            # The use of LLIL_REG_IS_TEMP is correct here, as there is no MLIL equivalent
            # and it seem to use the same underlying data
            if bn.LLIL_REG_IS_TEMP(item_or_list.storage):
                return results
            # We only care about registers that represent pointers.
            if item_or_list.type.type_class == bn.TypeClass.PointerTypeClass:
                if (
                    item_or_list.source_type
                    == bn.VariableSourceType.RegisterVariableSourceType
                ):
                    reg_name = program.bv.arch.get_reg_name(item_or_list.storage)
                    results.append(
                        (reg_name, program.type_cache.get(item_or_list.type), None)
                    )
        return results

    def _extract_types(
        self, program, item_or_list, initial_inst: llinst
    ) -> List[Tuple[str, Type, Optional[int]]]:
        """
        This function decomposes a list of LLIL instructions and associates registers with pointer values
        if they exist. If an MLIL instruction exists for the current instruction, it uses the MLIL to get more
        information about otherwise implicit operands and their types if available. (ex, a call instruction has
        rdi, rsi as operands in the MLIL, we should check if they have pointer information)
        """
        results = []
        if isinstance(item_or_list, list):
            for item in item_or_list:
                results.extend(self._extract_types(program, item, initial_inst))
        elif isinstance(item_or_list, llinst):
            results.extend(
                self._extract_types(program, item_or_list.operands, initial_inst)
            )
        elif isinstance(item_or_list, bn.lowlevelil.ILRegister):
            # Check if the register is not temp. Need to check if the temp register is
            # associated to pointer?? Look into MLIL to get more information
            if (not bn.LLIL_REG_IS_TEMP(item_or_list.index)) and (
                item_or_list.name not in ["x87control", "x87status"]
            ):
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
                    results.append(
                        (item_or_list.name, val_type, possible_pointer.value)
                    )

            if initial_inst.mlil is not None:
                mlil_results = self._extract_types_mlil(
                    program, initial_inst.mlil, initial_inst.mlil
                )
                results.extend(mlil_results)
        return results

    def _fill_bytes(self, program, memory, start, end, ref_eas):
        br = bn.BinaryReader(program.bv)
        for bb in self._bn_func.basic_blocks:
            for ea in range(bb.start, bb.end):
                seg = program.bv.get_segment_at(ea)
                br.seek(ea)
                memory.map_byte(ea, br.read8(), seg.writable, seg.executable)
                inst = self._bn_func.get_low_level_il_at(ea)
                if inst and not is_unimplemented(program.bv, inst):
                    _collect_xrefs_from_inst(program.bv, inst, ref_eas)


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


def _collect_xrefs_from_inst(bv, inst, ref_eas, reftype=XrefType.XREF_NONE):
    """Recursively collect xrefs in a IL instructions"""
    if not isinstance(inst, bn.LowLevelILInstruction):
        return

    if is_unimplemented(bv, inst) or is_undef(bv, inst):
        return

    if is_function_call(bv, inst) or is_jump(bv, inst):
        reftype = XrefType.XREF_CONTROL_FLOW

    elif is_memory_inst(bv, inst) or is_unimplemented_mem(bv, inst):
        mem_il = inst.dest if is_store_inst(bv, inst) else inst.src

        if is_constant(bv, mem_il):
            reftype = XrefType.XREF_MEMORY
        else:
            reftype = XrefType.XREF_DISPLACEMENT

        _collect_xrefs_from_inst(bv, mem_il, ref_eas, reftype)

        for opnd in inst.operands:
            _collect_xrefs_from_inst(bv, opnd, ref_eas)

    elif is_constant_pointer(bv, inst):
        const_ea = inst.constant
        if is_code(bv, const_ea) and not XrefType.is_memory(bv, reftype):
            ref_eas.add(const_ea)
        elif is_data(bv, const_ea):
            ref_eas.add(const_ea)

    # Recursively look for the xrefs in operands
    for opnd in inst.operands:
        _collect_xrefs_from_inst(bv, opnd, ref_eas, reftype)


def is_constant(bv, inst):
    return inst.operation in (
        bn.LowLevelILOperation.LLIL_CONST,
        bn.LowLevelILOperation.LLIL_CONST_PTR,
    )


def is_constant_pointer(bv, inst):
    return inst.operation == bn.LowLevelILOperation.LLIL_CONST_PTR


def is_function_call(bv, inst):
    return inst.operation in (
        bn.LowLevelILOperation.LLIL_CALL,
        bn.LowLevelILOperation.LLIL_TAILCALL,
        bn.LowLevelILOperation.LLIL_CALL_STACK_ADJUST,
    )


def is_jump(bv, inst):
    return inst.operation in (
        bn.LowLevelILOperation.LLIL_JUMP,
        bn.LowLevelILOperation.LLIL_JUMP_TO,
    )


def is_load_inst(bv, inst):
    return inst.operation == bn.LowLevelILOperation.LLIL_LOAD


def is_store_inst(bv, inst):
    return inst.operation == bn.LowLevelILOperation.LLIL_STORE


def is_memory_inst(bv, inst):
    return is_load_inst(bv, inst) or is_store_inst(bv, inst)


def is_unimplemented(bv, inst):
    return inst.operation == bn.LowLevelILOperation.LLIL_UNIMPL


def is_unimplemented_mem(bv, inst):
    return inst.operation == bn.LowLevelILOperation.LLIL_UNIMPL_MEM


def is_undef(bv, inst):
    return inst.operation == bn.LowLevelILOperation.LLIL_UNDEF


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
