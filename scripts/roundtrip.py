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

import unittest
import subprocess
import argparse
import tempfile
import os
import sys

class RunError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return str(self.msg)


def run_cmd(cmd, timeout):
    try:
        sys.stdout.write("Running: %s\n" % ' '.join(cmd))
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            universal_newlines=True,
        )
    except FileNotFoundError as e:
        raise RunError('Error: No such file or directory: "' + e.filename + '"')
    except PermissionError as e:
        raise RunError('Error: File "' + e.filename + '" is not an executable.')

    return p


def compile(self, clang, input, output, timeout, options=None):
    cmd = []
    cmd.append(clang)
    if options is not None:
        cmd.extend(options)
    cmd.extend([input, "-o", output])
    p = run_cmd(cmd, timeout)

    self.assertEqual(p.returncode, 0, "clang failure")
    self.assertEqual(
        len(p.stderr), 0, "errors or warnings during compilation: %s" % p.stderr
    )

    return p


def specify(self, specifier, input, output, timeout):
    cmd = list(specifier) if isinstance(specifier, list) else [specifier]
    cmd.extend(["--bin_in", input])
    cmd.extend(["--spec_out", output])
    cmd.extend(["--entry_point", "main"])
    p = run_cmd(cmd, timeout)

    self.assertEqual(p.returncode, 0, "specifier failure: %s" % p.stderr)
    self.assertEqual(
        len(p.stderr), 0, "errors or warnings during specification: %s" % p.stderr
    )

    return p


def decompile(self, decompiler, input, output, timeout):
    cmd = [decompiler]
    cmd.extend(["--spec", input])
    cmd.extend(["--bc_out", output])
    p = run_cmd(cmd, timeout)

    self.assertEqual(p.returncode, 0, "decompiler failure: %s" % p.stderr)
    self.assertEqual(
        len(p.stderr), 0, "errors or warnings during decompilation: %s" % p.stderr
    )

    return p


def roundtrip(self, specifier, decompiler, filename, testname, clang, timeout):
    with tempfile.TemporaryDirectory() as tempdir:
        compiled = os.path.join(tempdir, f"{testname}_compiled")
        compile(self, clang, filename, compiled, timeout)

        # capture binary run outputs
        compiled_output = run_cmd([compiled], timeout)

        rt_json = os.path.join(tempdir, f"{testname}_rt.json")
        specify(self, specifier, compiled, rt_json, timeout)

        rt_bc = os.path.join(tempdir, f"{testname}_rt.bc")
        decompile(self, decompiler, rt_json, rt_bc, timeout)

        rebuilt = os.path.join(tempdir, f"{testname}_rebuilt")
        compile(self, clang, rt_bc, rebuilt, timeout, ["-Wno-everything"]) 
        # capture outputs of binary after roundtrip
        rebuilt_output = run_cmd([rebuilt], timeout)

        self.assertEqual(compiled_output.stderr, rebuilt_output.stderr, "Different stderr")
        self.assertEqual(compiled_output.stdout, rebuilt_output.stdout, "Different stdout")
        self.assertEqual(compiled_output.returncode, rebuilt_output.returncode, "Different return code")


class TestRoundtrip(unittest.TestCase):
    pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("anvill", help="path to anvill-decompile-json")
    parser.add_argument("tests", help="path to test directory")
    parser.add_argument("clang", help="path to clang")
    parser.add_argument("-t", "--timeout", help="set timeout in seconds", type=int)

    args = parser.parse_args()

    def test_generator(path, test_name):
        def test(self):
            specifier = ["python3", "-m", "anvill"]
            roundtrip(self, specifier, args.anvill, path, test_name, args.clang, args.timeout)

        return test

    for item in os.scandir(args.tests):
        test_name = "test_%s" % os.path.splitext(item.name)[0]
        test = test_generator(item.path, test_name)
        setattr(TestRoundtrip, test_name, test)

    unittest.main(argv=[sys.argv[0], "-v"])
