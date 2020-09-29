#!/usr/bin/env python3

import unittest
import subprocess
import argparse
import tempfile
import os
import sys

import anvill

class RunError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return str(self.msg)


def run_cmd(cmd, timeout):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,
                           timeout=timeout, universal_newlines=True)
    except FileNotFoundError as e:
        raise RunError(
            "Error: No such file or directory: \"" +
            e.filename +
            "\"")
    except PermissionError as e:
        raise RunError(
            "Error: File \"" +
            e.filename +
            "\" is not an executable.")

    return p


def compile(self, clang, input, output, timeout, options=None):
    cmd = []
    cmd.append(clang)
    if options is not None:
        cmd.extend(options)
    cmd.extend([input, "-o", output])
    p = run_cmd(cmd, timeout)

    self.assertEqual(p.returncode, 0, "clang failure")
    self.assertEqual(len(p.stderr), 0,
                     "errors or warnings during compilation: %s" % p.stderr)

    return p


def specify(self, input, output):
    p = anvill.get_program(input)
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
            break
    
    for f in s:
        p.add_symbol(f.address(), f.name())
        p.add_function_definition(f.address(), False)

    spec = p.proto()
    
    self.assertNotEqual(len(spec), 0, "empty json specification")

    with open(output, "w") as f:
        f.write(spec)
    
    return


def decompile(self, decompiler, input, output, timeout):
    cmd = [decompiler]
    cmd.extend(["--spec", input])
    cmd.extend(["--bc_out", output])
    p = run_cmd(cmd, timeout)

    self.assertEqual(p.returncode, 0, "decompiler failure: %s" % p.stderr)
    self.assertEqual(len(p.stderr), 0,
                     "errors or warnings during decompilation: %s" % p.stderr)

    return p


def roundtrip(self, decompiler, filename, clang, timeout):
    with tempfile.TemporaryDirectory() as tempdir:
        out1 = os.path.join(tempdir, "out1")
        compile(self, clang, filename, out1, timeout)

        # capture binary run outputs
        cp1 = run_cmd([out1], timeout)

        rt_json = os.path.join(tempdir, "rt.json")
        specify(self, out1, rt_json)

        rt_bc = os.path.join(tempdir, "rt.bc")
        decompile(self, decompiler, rt_json, rt_bc, timeout)

        out2 = os.path.join(tempdir, "out2")
        compile(self, clang, rt_bc, out2, timeout, ["-Wno-everything"])

        # capture outputs of binary after roundtrip
        cp2 = run_cmd([out2], timeout)

        self.assertEqual(cp1.stderr, cp2.stderr, "Different stderr")
        self.assertEqual(cp1.stdout, cp2.stdout, "Different stdout")
        self.assertEqual(cp1.returncode, cp2.returncode,
                         "Different return code")


class TestRoundtrip(unittest.TestCase):
    pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("anvill", help="path to anvill-decompile-json")
    parser.add_argument("tests",
                        help="path to test directory")
    parser.add_argument("clang", help="path to clang")
    parser.add_argument(
        "-t",
        "--timeout",
        help="set timeout in seconds",
        type=int)

    args = parser.parse_args()

    def test_generator(path):
        def test(self):
            roundtrip(self, args.anvill, path, args.clang, args.timeout)
        return test

    for item in os.scandir(args.tests):
        test_name = 'test_%s' % os.path.splitext(item.name)[0]
        test = test_generator(item.path)
        setattr(TestRoundtrip, test_name, test)

    unittest.main(argv=[sys.argv[0]])
