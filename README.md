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

## `anvill-decompile-json`

`anvill-decompile-json` is a specification-based decompiler. That is,
this tool will decompile machine code into high-quality bitcode given
a specification describing the input and output locations and
types of compiled functions, as well as type and location information
about any of their dependencies.
