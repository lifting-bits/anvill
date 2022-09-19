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
import traceback
from typing import cast, Optional

import binaryninja as bn
from anvill import ERROR

from .exc import InvalidVariableException
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


    arg_parser.add_argument("--entrypoint", type=str, help="only specify functions from entrypoint")

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

    flist = bv.functions

    if args.entrypoint and len(bv.get_functions_by_name(args.entrypoint)) == 0 and len(bv.get_functions_by_name("_"+args.entrypoint)) != 0:
        args.entrypoint = "_"+args.entrypoint


    if args.entrypoint:
        epoint = None
        if len(bv.get_functions_by_name(args.entrypoint)) > 0:
            target = bv.get_functions_by_name(args.entrypoint)[0]
            epoint = target.start
        else:
            epoint = int(args.entrypoint, 16)

        newflsit = set()
        bv.add_function(epoint)
        func = next(filter(lambda f: f.start == epoint,bv.functions))
        worklist = [func]
        while worklist:
            curr = worklist.pop()
            if curr in worklist:
                continue

            newflsit.add(curr)
             
            for f in curr.callees:
                if f not in newflsit:
                    worklist.append(f)
        flist = newflsit

    for f in flist:
        ea: int = f.start
        DEBUG(f"Found function at: {ea:x}")
        try:
            p.add_function_definition(ea, True)
        except:
            ERROR(f"Error when trying to add function {ea:x}: {traceback.format_exc()}")

    for s_ in bv.get_symbols():
        s = cast(bn.Symbol, s_)
        ea, name = s.address, s.name
        DEBUG(f"Looking at symbol {name}")
        if s.name != "_start" or bv.get_symbol_at(ea).name == s.name:
            # extern symbols use original symbol name
            for sec in bv.get_sections_at(ea):
                if sec.name == ".extern":
                    DEBUG(f"Adding extern {name}")
                    p.add_symbol(ea, f"{name}")
                    break
            else:
                # main use original symbol name
                # Global and Weak bindings use original name
                if name == "main" or \
                   s.binding == bn.SymbolBinding.GlobalBinding or \
                   s.binding == bn.SymbolBinding.WeakBinding:
                    DEBUG(f"Adding {name}")
                    p.add_symbol(ea, f"{name}")
                else:
                    # all other symbols postfixed with address of symbol
                    DEBUG(f"Adding symbol {name}_{ea:x}")
                    p.add_symbol(ea, f"{name}_{ea:x}")

        if s.type == bn.SymbolType.FunctionSymbol:
            continue  # Already added as a function.

        elif s.type == bn.SymbolType.ExternalSymbol:
            v = bv.get_data_var_at(ea)
            if v is not None and isinstance(v.type, bn.FunctionType):
                DEBUG(f"Adding extern func {s.name} {ea:x}")
                p.add_function_declaration(ea, False)
            else:
                DEBUG(f"Adding extern var {s.name} {ea:x}")
                p.add_variable_declaration(ea, False)

        elif s.type == bn.SymbolType.LibraryFunctionSymbol or \
             s.type == bn.SymbolType.ImportedFunctionSymbol or \
             s.type == bn.SymbolType.ImportAddressSymbol:
            continue  # TODO(pag): Handle me?

        else:
            try:
                DEBUG(f"Found variable at: {ea:x}")
                p.add_variable_definition(ea, True)
            except:
                ERROR(f"Error when trying to add variable {ea:x}: {traceback.format_exc()}")


    with open(args.spec_out, "w") as f:
        f.write(json.dumps(p.proto(), indent="  "))

    return 0

if __name__ == "__main__":
    exit(main())
