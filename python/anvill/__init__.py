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
