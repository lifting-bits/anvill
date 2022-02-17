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
    binary_path: Optional[str] = None,
    binary_view: Optional[bn.BinaryView] = None,
    base_address: Optional[int] = None,
) -> Optional[Specification]:
    if isinstance(binary_path, str):
        if isinstance(base_address, int):
            # Force the new image base address; according to the
            # documentation, we will
            # not inherit any of the default load options that we get when
            # calling the
            # get_view_of_file method
            binary_view = bn.BinaryViewType.get_view_of_file_with_options(
                binary_path, options={"loader.imageBase": base_address}
            )

        else:
            # Use the auto-generated load options
            binary_view = bn.BinaryViewType.get_view_of_file(binary_path)
    elif isinstance(binary_view, bn.BinaryView):
        try:
            binary_path = binary_view.file.filename
        except:
            pass
        assert base_address is None


    if binary_view is None:
        DEBUG("Failed to create the BinaryView")
        return None

    DEBUG("Recovering program {}".format(binary_path))
    return BNSpecification(binary_view, binary_path)
