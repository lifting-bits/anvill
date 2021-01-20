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

import argparse

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

    args, _ = arg_parser.parse_known_args()

    p = get_program(args.bin_in)
    funcs = {}
    ep = None

    if args.entry_point is not None:
        try:
            ep = int(args.entry_point, 0)
        except ValueError:
            ep = args.entry_point

    def add_callees(ea):
        f = p.get_function(ea)
        if f not in funcs:
            funcs[ea] = f.name()
            for c in f._bn_func.callees:
                add_callees(c.start)

    for ea, name in p.functions:
        if not ep:
            funcs[ea] = p.get_function(ea).name()
        elif ep == (ea if isinstance(ep, int) else name):
            add_callees(ea)
            break

    for ea in funcs:
        p.add_symbol(ea, funcs[ea])
        p.add_function_definition(ea, True)
       
    for ea, v in p.variables:
        for r in v.code_refs:
            if r.function.start in funcs:
                p.add_variable_definition(ea, False)

    open(args.spec_out, "w").write(p.proto())


if __name__ == "__main__":
    exit(main())
