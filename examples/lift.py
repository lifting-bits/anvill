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
    for addr, name in p.functions:
        p.add_symbol(addr, name)
        p.add_function_definition(addr, False)
    open(args.spec_out, "w").write(p.proto())

if __name__ == "__main__":
  exit(main())