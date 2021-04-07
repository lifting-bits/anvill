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


import ida_segment
import idc
import ida_xref
import ida_idaapi
import ida_fixup


def find_segment_containing_ea(ea, seg_ref):
    """Find and return a `segment_t` containing `ea`, or `None`."""
    seg = seg_ref[0]
    if seg and seg.contains(ea):
        return seg

    seg = ida_segment.get_first_seg()
    while seg:
        seg_ref[0] = seg
        if seg.contains(ea):
            return seg
        seg = ida_segment.get_next_seg(seg.start_ea)

    return None


def is_imported_table_seg(seg):
    """Returns `True` if `seg` refers to a segment that typically contains
    import entries, i.e. cross-reference pointers into an external segment."""
    if not seg:
        return False

    seg_name = idc.get_segm_name(seg.start_ea)
    return ".idata" in seg_name or ".plt" in seg_name or ".got" in seg_name


def xref_generator(ea, seg_ref):
    """Generate all outbound cross-references from `ea`"""
    for ref_ea in _xref_iterator(
        ea, ida_xref.get_first_cref_from, ida_xref.get_next_cref_from
    ):
        if find_segment_containing_ea(ref_ea, seg_ref):
            yield ref_ea

    for ref_ea in _xref_iterator(
        ea, ida_xref.get_first_dref_from, ida_xref.get_next_dref_from
    ):
        if find_segment_containing_ea(ref_ea, seg_ref):
            yield ref_ea

    fd = ida_fixup.fixup_data_t()
    if fd.get(ea):
        if find_segment_containing_ea(fd.off, seg_ref):
            yield fd.off
            # TODO(pag): What about `fd.displacement`?


def _xref_iterator(ea, get_first, get_next):
    """Generate the cross-references addresses using functors `get_first` and
    `get_next`."""
    target_ea = get_first(ea)
    while target_ea != ida_idaapi.BADADDR:
        yield target_ea
        target_ea = get_next(ea, target_ea)
