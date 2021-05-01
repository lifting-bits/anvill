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


from .utils import *


from anvill.var import *


class IDAVariable(Variable):

    __slots__ = ("_ida_seg",)

    def __init__(self, arch, address, type_, ida_seg):
        super(IDAVariable, self).__init__(arch, address, type_)
        self._ida_seg = ida_seg

    def visit(self, program, is_definition, add_refs_as_defs):
        seg_ref = [None]
        seg = find_segment_containing_ea(self.address(), seg_ref)
        if seg and is_imported_table_seg(seg):
            DEBUG("Variable at {:x} is in an import table!".format(self.address()))
            is_definition = True

        if not is_definition:
            return

        memory = program.memory
        # TODO
