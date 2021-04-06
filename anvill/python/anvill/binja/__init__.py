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


from .bnprogram import *


from anvill.util import *


def get_program(arg, cache=False):
    if cache:
        DEBUG("Ignoring deprecated `cache` parameter to anvill.get_program")

    path: Optional[str] = None
    bv: Optional[bn.BinaryView] = None
    if isinstance(arg, str):
        path = arg
        bv = bn.BinaryViewType.get_view_of_file(path)
    elif isinstance(arg, bn.BinaryView):
        bv = arg
        path = bv.file.original_filename
    else:
        return None

    DEBUG("Recovering program {}".format(path))
    prog = BNProgram(bv, path)
    return prog
