#!/usr/bin/env python3
# Copyright 2020, Trail of Bits, Inc. All rights reserved.

import argparse
import anvill

def main():
    arg_parser = argparse.ArgumentParser()
    
    arg_parser.add_argument(
        '--bin_in',
        help='Path to input binary.',
        required=True)
    
    arg_parser.add_argument(
        '--spec_out',
        help='Path to output JSON specification.',
        required=True)
    
    args, _ = arg_parser.parse_known_args()

    p = anvill.get_program(args.bin_in)
    s = set()
    
    def add_callees(ea):
        f = p.get_function(ea)
        if f not in s:
            s.add(f)
            for c in f._bn_func.callees:
                add_callees(c.start)
            
    for ea, name in p.functions:
        if name == "main":
            add_callees(ea)
    
    for f in s:
        p.add_symbol(f.address(), f.name())
        p.add_function_definition(f.address(), False)

    open(args.spec_out, "w").write(p.proto())

if __name__ == "__main__":
  exit(main())