#!/usr/bin/env python3

#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

import unittest
import subprocess
import argparse
import tempfile
import os
import platform
import sys
import shutil


class RunError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return str(self.msg)


def write_command_log(cmd_description, cmd_exec, ws):
    with open(os.path.join(ws, "commands.log"), "a") as cmdlog:
        if cmd_description:
            cmdlog.write(f"# {cmd_description}\n")
        cmdlog.write(f"{cmd_exec}\n")


def run_cmd(cmd, timeout, description, ws):
    try:
        exec_cmd = f"{' '.join(cmd)}"
        sys.stdout.write(f"Running: {exec_cmd}\n")
        write_command_log(description, exec_cmd, ws)
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            universal_newlines=True,
        )
    except FileNotFoundError as e:
        raise RunError('Error: No such file or directory: "' +
                       e.filename + '"')
    except PermissionError as e:
        raise RunError('Error: File "' + e.filename +
                       '" is not an executable.')

    return p


def compile(self, clang, input, output, timeout, ws, options=None):
    cmd = []
    cmd.append(clang)
    if options is not None:
        cmd.extend(options)
    cmd.extend([input, "-o", output])
    p = run_cmd(
        cmd, timeout, description="Original source Clang compile command", ws=ws)

    self.assertEqual(p.returncode, 0, "clang failure")
    self.assertEqual(
        len(p.stderr), 0, "errors or warnings during compilation: %s" % p.stderr
    )

    return p


def specify(self, specifier, input, output, timeout, ws):
    cmd = list(specifier) if isinstance(specifier, list) else [specifier]
    cmd.extend(["--bin_in", input])
    cmd.extend(["--spec_out", output])
    cmd.extend(["--entry_point", "main"])
    cmd.extend(["--refs_as_defs"])
    p = run_cmd(cmd, timeout, description="Spec generation command", ws=ws)

    self.assertEqual(p.returncode, 0, "specifier failure: %s" % p.stderr)
    self.assertEqual(
        len(p.stderr), 0, "errors or warnings during specification: %s" % p.stderr
    )

    return p


def decompile(self, decompiler, input, output, timeout, ws):
    cmd = [decompiler]
    cmd.extend(["--spec", input])
    cmd.extend(["--bc_out", output])
    p = run_cmd(cmd, timeout, description="Decompilation command", ws=ws)

    self.assertEqual(p.returncode, 0, "decompiler failure: %s" % p.stderr)
    self.assertEqual(
        len(p.stderr), 0, "errors or warnings during decompilation: %s" % p.stderr
    )

    return p


def roundtrip(self, specifier, decompiler, filename, testname, clang, timeout, workspace):

    # Python refuses to add delete=False to the TemporaryDirectory constructor
    # with tempfile.TemporaryDirectory(prefix=f"{testname}_", dir=workspace) as tempdir:
    tempdir = tempfile.mkdtemp(prefix=f"{testname}_", dir=workspace)

    compiled = os.path.join(tempdir, f"{testname}_compiled")
    compile(self, clang, filename, compiled, timeout, tempdir)

    # capture binary run outputs
    compiled_output = run_cmd(
        [compiled], timeout, description="capture compilation output", ws=tempdir)

    rt_json = os.path.join(tempdir, f"{testname}_rt.json")
    specify(self, specifier, compiled, rt_json, timeout, tempdir)

    rt_bc = os.path.join(tempdir, f"{testname}_rt.bc")
    decompile(self, decompiler, rt_json, rt_bc, timeout, tempdir)

    rebuilt = os.path.join(tempdir, f"{testname}_rebuilt")
    compile(self, clang, rt_bc, rebuilt, timeout, tempdir, ["-Wno-everything"])
    # capture outputs of binary after roundtrip
    rebuilt_output = run_cmd(
        [rebuilt], timeout, description="Capture binary output after roundtrip", ws=tempdir)

    # Clean up tempdir if no workspace specified
    # otherwise keep it for debugging purposes
    if not workspace:
        shutil.rmtree(tempdir)

    self.assertEqual(compiled_output.stderr,
                     rebuilt_output.stderr, "Different stderr")
    self.assertEqual(compiled_output.stdout,
                     rebuilt_output.stdout, "Different stdout")
    self.assertEqual(compiled_output.returncode,
                     rebuilt_output.returncode, "Different return code")


class TestRoundtrip(unittest.TestCase):
    pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("anvill", help="path to anvill-decompile-json")
    parser.add_argument("tests", help="path to test directory")
    parser.add_argument("clang", help="path to clang")
    parser.add_argument("workspace", nargs="?", default=None,
                        help="Where to save temporary unit test outputs")
    parser.add_argument("-t", "--timeout",
                        help="set timeout in seconds", type=int)

    args = parser.parse_args()

    if args.workspace:
        os.makedirs(args.workspace)

    def test_generator(path, test_name):
        def test(self):
            specifier = ["python3", "-m", "anvill"]
            roundtrip(self, specifier, args.anvill, path, test_name,
                      args.clang, args.timeout, args.workspace)

        return test

    for item in os.scandir(args.tests):
        test_name = "test_%s" % os.path.splitext(item.name)[0]
        test = test_generator(item.path, test_name)
        setattr(TestRoundtrip, test_name, test)

    unittest.main(argv=[sys.argv[0], "-v"])
