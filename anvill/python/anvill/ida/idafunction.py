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


import ida_funcs
import ida_segment
import idc
import ida_bytes


from .utils import *


from anvill.function import *


_OPERANDS_NUMS = (0, 1, 2)
_REF_OPERAND_TYPES = (
    idc.o_phrase,
    idc.o_displ,
    idc.o_imm,
    idc.o_far,
    idc.o_near,
    idc.o_mem,
)


class IDAFunction(Function):

    __slots__ = ("_pfn", "_is_noreturn")

    def __init__(
        self, arch, address, param_list, ret_list, ida_func, is_noreturn, func_type, cc
    ):
        super(IDAFunction, self).__init__(
            arch, address, param_list, ret_list, func_type, cc
        )
        self._pfn = ida_func
        self._is_noreturn = is_noreturn

    def is_noreturn(self):
        return self._is_noreturn

    def visit(self, program, is_definition, add_refs_as_defs):
        if not is_definition:
            return

        memory = program.memory()

        seg_ref = [None]

        ref_eas = set()

        # Map the continuous range of bytes associated with the main body of the
        # function. We might get a bit beyond that, as our function bounds stuff
        # looks for previous and next function locations.
        ea, max_ea = _get_function_bounds(self._pfn, seg_ref)

        while ea < max_ea:
            if not _try_map_byte(memory, ea, seg_ref):
                break
            _collect_xrefs_from_func(self._pfn, ea, ref_eas, seg_ref)
            ea += 1

        # Map the bytes of function chunks. These are discontinuous parts of a
        # function, e.g. cold code put off the critical path to reduce icache
        # pressure.
        fti = ida_funcs.func_tail_iterator_t(self._pfn)
        ok = fti.first()
        while ok:
            chunk = fti.chunk()
            ea = chunk.start_ea
            max_ea = chunk.end_ea
            while ea < max_ea:
                if not _try_map_byte(memory, ea, seg_ref):
                    break
                _collect_xrefs_from_func(self._pfn, ea, ref_eas, seg_ref)
                ea += 1

            ok = fti.next()

        # Now go and inspect cross-referenced date/code, and add it to the program.
        for ref_ea in ref_eas:
            _visit_ref_ea(program, ref_ea, add_refs_as_defs)


def _try_map_byte(memory, ea, seg_ref):
    """Try to map a byte into memory."""
    seg = find_segment_containing_ea(ea, seg_ref)
    if not seg:
        return False

    can_write = 0 != (seg.perm & ida_segment.SEGPERM_WRITE)
    can_exec = _is_executable_seg(seg)

    val = 0
    if ida_bytes.has_value(ida_bytes.get_full_flags(ea)):
        val = ida_bytes.get_wide_byte(ea) & 0xFF

    flags = ida_bytes.get_full_flags(ea)
    memory.map_byte(ea, val, can_write, can_exec)
    return True


def _is_executable_seg(seg):
    """Returns `True` a segment's data is executable."""
    if 0 != (seg.perm & ida_segment.SEGPERM_EXEC):
        return True

    seg_type = idc.get_segm_attr(seg.start_ea, idc.SEGATTR_TYPE)
    if seg_type in (idc.SEG_CODE, idc.SEG_XTRN):
        return True

    sclass = ida_segment.get_segm_class(seg)
    if sclass:
        return "CODE" in sclass or "XTRN" in sclass

    return False


def _get_function_bounds(func, seg_ref):
    """Get the bounds of the function containing `ea`. We want to discover jump
    table targets that are missed by IDA, and it's possible that they aren't
    marked as being part of the current function, and perhaps are after the
    assumed range of the current function. Ideally they will fall before the
    beginning of the next function, though.

    We need to be pretty careful with the case that one function tail-calls
    another. IDA will sometimes treat the end of the tail-called function
    (e.g. a thunk) as if it is the end of the caller. For this reason, we start
    with loose bounds using the prev/next functions, then try to narrow with
    the bounds of the function containing `ea`.

    NOTE(pag): This does not handle function chunks.
    """
    ea = func.start_ea
    seg = find_segment_containing_ea(ea, seg_ref)
    if not seg:
        return ea, ea

    seg_start, seg_end = seg.start_ea, seg.end_ea
    min_ea = seg_start
    max_ea = seg_end

    if not _is_executable_seg(seg):
        return ea, ea

    # Get an upper bound using the next function.
    has_upper = False
    next_func = ida_funcs.get_next_func(ea)
    if next_func:
        next_func_seg = find_segment_containing_ea(next_func.start_ea, seg_ref)
        if next_func_seg and _is_executable_seg(next_func_seg):
            max_ea = min(next_func.start_ea, max_ea)
            has_upper = True

    # Get a lower bound using the previous function.
    has_lower = False
    prev_func = ida_funcs.get_prev_func(ea)
    if prev_func:
        prev_func_seg = find_segment_containing_ea(prev_func.start_ea, seg_ref)
        if prev_func_seg and _is_executable_seg(prev_func_seg):
            min_ea = max(prev_func.end_ea, min_ea)
            has_lower = True

    # Try to tighten the bounds using the function containing `ea`.
    if not has_lower:
        min_ea = max(min_ea, func.start_ea)

    if not has_upper:
        max_ea = min(max_ea, func.end_ea)

    return min_ea, max_ea


def _visit_ref_ea(program, ref_ea, add_refs_as_defs):
    """Try to add `ref_ea` as some referenced entity."""
    if not program.try_add_referenced_entity(ref_ea, add_refs_as_defs):
        seg_ref = [None]
        seg = find_segment_containing_ea(ref_ea, seg_ref)
        if seg:
            print("Unable to add {:x} as a variable or function".format(ref_ea))


def _collect_xrefs_from_func(pfn, ea, out_ref_eas, seg_ref):
    """Collect cross-references at `ea` in `pfn` that target code/data
    outside of `pfn`. Save them into `out_ref_eas`."""
    global _OPERANDS_NUMS

    # TODO(pag): Decode instruction at `ea`, iterate over operands, and try
    #            to build up operand-specific refs, using a mechanism similar
    #            to McSema's `get_instruction_references`. Might want to pass
    #            in a boolean argument to tell us if IDA thinks this is an
    #            instruction head.
    for ref_ea in xref_generator(ea, seg_ref):
        if not ida_funcs.func_contains(pfn, ref_ea):
            out_ref_eas.add(ref_ea)
            _add_real_xref(ea, ref_ea, out_ref_eas)


def _add_real_xref(ea, ref_ea, out_ref_eas):
    """Sometimes IDA will have a operand like `[foo+10]` and the xref collector
    will give us the address of `foo`, but not the address of `foo+10`, so we
    will try to find it here."""
    global _OPERANDS_NUMS, _REF_OPERAND_TYPES

    ref_name = ida_name.get_ea_name(ref_ea)
    for i in _OPERANDS_NUMS:

        try:
            op_type = idc.get_operand_type(ea, i)
        except:
            return

        if op_type not in _REF_OPERAND_TYPES:
            continue

        op_str = idc.print_operand(ea, i)
        if op_str is None:
            return

        if ref_name in op_str:
            op_val = idc.get_operand_value(ea, i)
            out_ref_eas.add(op_val)
