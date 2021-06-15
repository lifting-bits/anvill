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
from typing import Optional


def is_constant(bv, inst):
    if isinstance(inst, bn.LowLevelILInstruction):
        return inst.operation in (
            bn.LowLevelILOperation.LLIL_CONST,
            bn.LowLevelILOperation.LLIL_CONST_PTR,
        )

    elif isinstance(inst, bn.MediumLevelILInstruction):
        return inst.operation in (
            bn.MediumLevelILOperation.MLIL_CONST,
            bn.MediumLevelILOperation.MLIL_CONST_PTR,
        )

    return False


def is_constant_pointer(bv, inst):
    if isinstance(inst, bn.LowLevelILInstruction):
        return inst.operation == bn.LowLevelILOperation.LLIL_CONST_PTR

    elif isinstance(inst, bn.MediumLevelILInstruction):
        return inst.operation == bn.MediumLevelILOperation.MLIL_CONST_PTR

    return False


def is_register_inst(bv, inst):
    if isinstance(inst, bn.LowLevelILInstruction):
        return inst.operation == bn.LowLevelILOperation.LLIL_REG

    return False


def is_function_call(bv, inst):
    if isinstance(inst, bn.LowLevelILInstruction):
        return inst.operation in (
            bn.LowLevelILOperation.LLIL_CALL,
            bn.LowLevelILOperation.LLIL_TAILCALL,
            bn.LowLevelILOperation.LLIL_CALL_STACK_ADJUST,
        )

    elif isinstance(inst, bn.MediumLevelILInstruction):
        return inst.operation in (
            bn.MediumLevelILOperation.MLIL_CALL,
            bn.MediumLevelILOperation.MLIL_TAILCALL,
            bn.MediumLevelILOperation.MLIL_CALL_UNTYPED,
        )

    return False


def is_function_tailcall(bv, inst):
    if isinstance(inst, bn.LowLevelILInstruction):
        return inst.operation in (bn.LowLevelILOperation.LLIL_TAILCALL,)

    elif isinstance(inst, bn.MediumLevelILInstruction):
        return inst.operation in (bn.MediumLevelILOperation.MLIL_TAILCALL,)

    return False


def is_jump(bv, inst):
    if isinstance(inst, bn.LowLevelILInstruction):
        return inst.operation in (bn.LowLevelILOperation.LLIL_JUMP,)

    elif isinstance(inst, bn.MediumLevelILInstruction):
        return inst.operation in (bn.MediumLevelILOperation.MLIL_JUMP,)

    return False


def is_jump_to(bv, inst):
    if isinstance(inst, bn.LowLevelILInstruction):
        return inst.operation in (bn.LowLevelILOperation.LLIL_JUMP_TO,)

    elif isinstance(inst, bn.MediumLevelILInstruction):
        return inst.operation in (bn.MediumLevelILOperation.MLIL_JUMP_TO,)

    return False


def is_load_inst(bv, inst):
    if isinstance(inst, bn.LowLevelILInstruction):
        return inst.operation == bn.LowLevelILOperation.LLIL_LOAD

    elif isinstance(inst, bn.MediumLevelILInstruction):
        return inst.operation == bn.MediumLevelILOperation.MLIL_LOAD

    return False


def is_store_inst(bv, inst):
    if isinstance(inst, bn.LowLevelILInstruction):
        return inst.operation in (bn.LowLevelILOperation.LLIL_STORE,)

    elif isinstance(inst, bn.MediumLevelILInstruction):
        return inst.operation in (bn.MediumLevelILOperation.MLIL_STORE,)

    return False


def is_memory_inst(bv, inst):
    return is_load_inst(bv, inst) or is_store_inst(bv, inst)


def is_import_address(bv, inst):
    if isinstance(inst, bn.MediumLevelILInstruction):
        return inst.operation == bn.MediumLevelILOperation.MLIL_IMPORT

    return False


def is_push_inst(bv, inst):
    if isinstance(inst, bn.LowLevelILInstruction):
        return inst.operation == bn.LowLevelILOperation.LLIL_PUSH

    return False


def is_unimplemented(bv, inst):
    if isinstance(inst, bn.LowLevelILInstruction):
        return inst.operation == bn.LowLevelILOperation.LLIL_UNIMPL

    elif isinstance(inst, bn.MediumLevelILInstruction):
        return inst.operation == bn.MediumLevelILOperation.MLIL_UNIMPL

    return False


def is_unimplemented_mem(bv, inst):
    if isinstance(inst, bn.LowLevelILInstruction):
        return inst.operation == bn.LowLevelILOperation.LLIL_UNIMPL_MEM

    elif isinstance(inst, bn.MediumLevelILInstruction):
        return inst.operation == bn.MediumLevelILOperation.MLIL_UNIMPL_MEM

    return False


def is_undef(bv, inst):
    if isinstance(inst, bn.LowLevelILInstruction):
        return inst.operation == bn.LowLevelILOperation.LLIL_UNDEF

    elif isinstance(inst, bn.MediumLevelILInstruction):
        return inst.operation == bn.MediumLevelILOperation.MLIL_UNDEF

    return False
