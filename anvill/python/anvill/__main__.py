#!/usr/bin/env python3

#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

import sys

import argparse
import json
from typing import cast, Optional

import binaryninja as bn
from anvill import ERROR

from .util import config_logger
from .util import DEBUG
from .binja import get_program


def main():

    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument(
        "--bin_in", help="Path to input binary.", required=True)

    arg_parser.add_argument(
        "--spec_out", help="Path to output JSON specification.", required=True)

    arg_parser.add_argument(
        "--log_file",
        type=str,
        default=None,
        help="Log to a specific file.")

    arg_parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Enable debug log for the module.")

    arg_parser.add_argument(
        "--base_address",
        type=str,
        help="Where the image should be loaded, expressed as an hex integer.")

    args = arg_parser.parse_args()

    # Configure logger
    config_logger(args.log_file, args.verbose)

    maybe_base_address: Optional[int] = None
    if args.base_address is not None:
        try:
            maybe_base_address = int(args.base_address, 16)
            DEBUG(
                f"Binary Ninja will attempt to load the image at virtual address {maybe_base_address:x}"
            )

        except:
            ERROR(f"The specified address it not valid: '{args.base_address}'")
            return 1

    p = get_program(binary_path=args.bin_in, base_address=maybe_base_address)
    if p is None:
        sys.stderr.write("FATAL: Could not initialize BinaryNinja's BinaryView\n")
        sys.stderr.write("Does BinaryNinja support this architecture?\n")
        return 1

    bv = cast(bn.BinaryView, p.bv)

    for f in bv.functions:
        ea: int = f.start
        DEBUG(f"Looking at binja found function at: {ea:x}")
        p.add_function_definition(ea, True)

    for s_ in bv.get_symbols():
        s = cast(bn.CoreSymbol, s_)
        ea, name = s.address, s.name
        p.add_symbol(ea, name)

        if s.type == bn.SymbolType.FunctionSymbol:
            continue  # Already added as a function.

        elif s.type == bn.SymbolType.ExternalSymbol:
            v = bv.get_data_var_at(ea)
            if v is not None and isinstance(v.type, bn.FunctionType):
                p.add_function_declaration(ea, False)
            else:
                p.add_variable_declaration(ea, False)

        elif s.type == bn.SymbolType.LibraryFunctionSymbol or \
             s.type == bn.SymbolType.ImportedFunctionSymbol:
            continue  # TODO(pag): Handle me?

        else:
            p.add_variable_definition(ea, True)

    with open(args.spec_out, "w") as f:
        f.write(json.dumps(p.proto(), indent="  "))

    return 0

if __name__ == "__main__":
    exit(main())
