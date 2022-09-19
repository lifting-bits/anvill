#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

import binaryninja as bn


from ..var import *
from ..type import *


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
            # ignore null pointer reference
            if ea == 0:
                continue

            # ignore data variables with no references
            var = bv.data_vars.get(ea)
            if var is not None and next(var.code_refs, None) is None and next(var.data_refs, None) is None:
                continue

            #NOTE(artem): This is a workaround for binary ninja's fake
            # .externs section, which is (correctly) mapped as
            # not readable, not writable, and not executable.
            # because it is a fictional creation of the disassembler.
            #
            # However, when we do control flow tragetting to thunks,
            # we will sanity check that the target goes to an executable
            # location. If we are lying about the target being readable,
            # then we may as well lie about it being executable.
            is_executable = seg.executable
            if seg.writable == seg.readable == False:
                is_executable = True

            mem.map_byte(ea, br.read8(), seg.writable, is_executable)
