from .arch import *
import os
try:
    import ida_idp
    from .ida import *
except ImportError as e:
    try:
        print("Trying binja!")
        import binaryninja
        license_file_path = "~/.binaryninja/license.dat"
        if os.getenv("BINJA_LICENSE") is not None:
            license_file_path = os.getenv("BINJA_LICENSE")
            if not os.path.exists(license_file_path):
                raise FileNotFoundError(f"Error! Could not find license file at {license_file_path}")
        # Load license
        with open(license_file_path, "r") as license_file:
            binaryninja.core_set_license(license_file.read())
        print("Importing .binja!")
        from .binja import *

    except ImportError as e:
        raise NotImplementedError("Could not find either IDA or Binary Ninja APIs")
