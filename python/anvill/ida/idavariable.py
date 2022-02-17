#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

from .utils import *


from ..util import *
from ..var import *


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
