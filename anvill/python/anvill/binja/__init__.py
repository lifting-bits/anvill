#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

from typing import Optional, Union


import binaryninja as bn


from .bnprogram import *


from ..util import *
from ..program import *


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
