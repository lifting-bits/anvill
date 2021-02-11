#!/usr/bin/env python3

# Copyright (c) 2020 Trail of Bits, Inc.
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

import os
import sys
import argparse
import json

from .util import INIT_DEBUG_FILE
from .binja import get_program


def main():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument("--bin_in", help="Path to input binary.", required=True)

    arg_parser.add_argument(
        "--spec_out", help="Path to output JSON specification.", required=True
    )

    arg_parser.add_argument(
        "--entry_point",
        type=str,
        help="Output functions only reachable from given entry point.",
    )

    arg_parser.add_argument(
        "--refs_as_defs",
        action="store_true",
        help="Output definitions of discovered functions and variables.",
        default=False,
    )

    arg_parser.add_argument(
        "--log_file",
        type=argparse.FileType('w'), default=os.devnull,
        help="Log to a specific file."
    )

    args = arg_parser.parse_args()

    if args.log_file != os.devnull:
        INIT_DEBUG_FILE(args.log_file)

    p = get_program(args.bin_in)

    ep = None
    if args.entry_point is not None:
        try:
            ep = int(args.entry_point, 0)
        except ValueError:
            ep = args.entry_point

    if ep is None:
        for ea in p.functions:
            p.add_function_definition(ea, args.refs_as_defs)
    elif isinstance(ep, int):
        p.add_function_definition(ep, args.refs_as_defs)
    else:
        for ea, name in p.symbols:
            if name == ep:
                p.add_function_definition(ea, args.refs_as_defs)

    def add_symbol(ea):
        for name in p.get_symbols(ea):
            p.add_symbol(ea, name)

    for f in p.proto()["functions"]:
        add_symbol(f["address"])

    for v in p.proto()["variables"]:
        add_symbol(v["address"])

    open(args.spec_out, "w").write(json.dumps(p.proto()))


if __name__ == "__main__":
    exit(main())
