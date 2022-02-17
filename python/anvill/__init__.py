#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

from .arch import *
import os

try:
    import ida_idp
    from .ida import *
except ImportError as e:
    try:
        import binaryninja
        from .binja import *

    except ImportError as e:
        raise NotImplementedError("Could not find either IDA or Binary Ninja APIs")
