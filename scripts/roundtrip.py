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


def roundtrip(self, specifier, decompiler, filename, clang, timeout):
    with tempfile.TemporaryDirectory() as tempdir:
        out1 = os.path.join(tempdir, "out1")
        compile(self, clang, filename, out1, timeout)

        # capture binary run outputs
        cp1 = run_cmd([out1], timeout)

        rt_json = os.path.join(tempdir, "rt.json")
        specify(self, specifier, out1, rt_json, timeout)

        rt_bc = os.path.join(tempdir, "rt.bc")
        decompile(self, decompiler, rt_json, rt_bc, timeout)

        out2 = os.path.join(tempdir, "out2")
        compile(self, clang, rt_bc, out2, timeout, ["-Wno-everything"])

        # capture outputs of binary after roundtrip
        cp2 = run_cmd([out2], timeout)

        self.assertEqual(cp1.stderr, cp2.stderr, "Different stderr")
        self.assertEqual(cp1.stdout, cp2.stdout, "Different stdout")
        self.assertEqual(cp1.returncode, cp2.returncode, "Different return code")


class TestRoundtrip(unittest.TestCase):
    pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("anvill", help="path to anvill-decompile-json")
    parser.add_argument("tests", help="path to test directory")
    parser.add_argument("clang", help="path to clang")
    parser.add_argument("-t", "--timeout", help="set timeout in seconds", type=int)

    args = parser.parse_args()

    def test_generator(path):
        def test(self):
            specifier = ["python3", "-m", "anvill"]
            roundtrip(self, specifier, args.anvill, path, args.clang, args.timeout)

        return test

    for item in os.scandir(args.tests):
        test_name = "test_%s" % os.path.splitext(item.name)[0]
        test = test_generator(item.path)
        setattr(TestRoundtrip, test_name, test)

    unittest.main(argv=[sys.argv[0]])
