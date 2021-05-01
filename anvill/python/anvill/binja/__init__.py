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


from typing import Optional, Union


import binaryninja as bn


from .bnprogram import *


from anvill.util import *
from anvill.program import *


def get_program(
    binary_path_or_bv: Union[str, bn.BinaryView],
    maybe_base_address: Optional[int] = None,
    cache: bool = False,
) -> Optional[Program]:
    if cache:
        DEBUG("Ignoring deprecated `cache` parameter to anvill.get_program")

    bv: Optional[bv.BinaryView] = None
    binary_path: str = ""

    if isinstance(binary_path_or_bv, bn.BinaryView):
        bv = binary_path_or_bv
        try:
            binary_path = bv.file.filename
        except:
            pass
        assert maybe_base_address is None

    elif isinstance(binary_path_or_bv, str):
        binary_path: str = binary_path_or_bv
        if maybe_base_address is not None:
            # Force the new image base address; according to the documentation, we will
            # not inherit any of the default load options that we get when calling the
            # get_view_of_file method
            bv = bn.BinaryViewType.get_view_of_file_with_options(
                binary_path, options={"loader.imageBase": maybe_base_address}
            )

        else:
            # Use the auto-generated load options
            bv = bn.BinaryViewType.get_view_of_file(binary_path)

    if bv is None:
        DEBUG("Failed to create the BinaryView")
        return None

    DEBUG("Recovering program {}".format(binary_path))
    return BNProgram(bv, binary_path)
