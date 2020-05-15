# ANVILL Decompiler Toolchain

This directory contains code that implements simple decompiler primitives
using Remill. The goal of these components is to produce high quality bitcode,
which can then be further decompiled to C (via Clang ASTs) using [Rellic](https://github.com/trailofbits/rellic.git). 

We define "high quality bitcode" as being similar in form to what the
Clang compiler would produce if it were executed on a semantically
equivalent C function.

## License

All code in this directory and all subdirectories is subject to the AGPL
v3 license. The details of that license can be found in [LICENSE](LICENSE).

## Building

**Note: Anvill requires at least LLVM 9.**

To build via Docker run, specify the architecture, base Ubuntu image and LLVM version. For example, to build Anvill linking against LLVM 9 on Ubuntu 20.04 on AMD64 do:

```
ARCH=amd64; DIST=ubuntu20.04; LLVM=900; \
   docker build . \
   -t anvill-llvm${LLVM}-${DIST}-${ARCH} \
   -f Dockerfile \
   --build-arg DISTRO_BASE=${DIST} \
   --build-arg ARCH=${ARCH} \
   --build-arg LLVM_VERSION=${LLVM}
```

## `anvill-decompile-json`

`anvill-decompile-json` is a specification-based decompiler. That is,
this tool will decompile machine code into high-quality bitcode given
a specification describing the input and output locations and
types of compiled functions, as well as type and location information
about any of their dependencies.

## `anvill-specify-json`

`anvill-specify-json` is a tool that produces specifications for all functions
contained in an LLVM bitcode module. The purpose of this tool is to enable
the creation of a database of specifications for commonly used, often externally-
defined functions in binaries (e.g. libc, libc++, libstdc++) in binaries lifted
by [McSema](https://github.com/lifting-bits/mcsema).

This tool also exists for enabling function declarations for binary code to be
written in C or C++, and then translated down into the specification form within
a decompiler toolchain.

Finally, this tool exists to enable round-trip testing of LLVM's ISEL lowering
and code generation for arbitrary functions.
