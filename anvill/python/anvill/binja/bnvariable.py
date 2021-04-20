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


from anvill.var import *
from anvill.type import *


class BNVariable(Variable):
    def __init__(self, bn_var, arch, address, type_):
        super(BNVariable, self).__init__(arch, address, type_)
        self._bn_var = bn_var

    def visit(self, program, is_definition, add_refs_as_defs):
        if not is_definition:
            return

        # type could be None if type class not handled
        if self._type is None:
            return

        if isinstance(self._type, VoidType):
            return

        bv = program.bv
        br = bn.BinaryReader(bv)
        mem = program.memory
        begin = self._address
        end = begin + self._type.size(self._arch)

        for ea in range(begin, end):
            br.seek(ea)
            seg = bv.get_segment_at(ea)
            # _elf_header is getting recovered as variable
            # get_segment_at(...) returns None for elf_header
            if seg is None:
                continue

            mem.map_byte(ea, br.read8(), seg.writable, seg.executable)
