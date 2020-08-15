# Anvill

Anvill implements simple machine code lifting primitives using Remill.
The goal of these components is to produce high quality bitcode,
which can then be further decompiled to C (via Clang ASTs) using
[Rellic](https://github.com/trailofbits/rellic.git).

We define "high quality bitcode" as being similar in form to what the
Clang compiler would produce if it were executed on a semantically
equivalent C function.

<!-- ## Build Status

|       | master |
| ----- | ------ |
| Linux | [![Build Status](https://github.com/lifting-bits/anvill/workflows/CI/badge.svg)](https://github.com/lifting-bits/anvill/actions?query=workflow%3ACI)| -->

## Getting Help

If you are experiencing undocumented problems with Anvill then ask for help in the `#binary-lifting` channel of the [Empire Hacking Slack](https://empireslacking.herokuapp.com/).

## Supported Platforms

Anvill is supported on Linux platforms and has been tested on Ubuntu 18.04 and 20.04.

## Dependencies

Most of Anvill's dependencies can be provided by the [cxx-common](https://github.com/trailofbits/cxx-common) repository. Trail of Bits hosts downloadable, pre-built versions of cxx-common, which makes it substantially easier to get up and running with Anvill. Nonetheless, the following table represents most of Anvill's dependencies.

| Name | Version |
| ---- | ------- |
| [Git](https://git-scm.com/) | Latest |
| [CMake](https://cmake.org/) | 3.2+ |
| [Google Flags](https://github.com/google/glog) | Latest |
| [Google Log](https://github.com/google/glog) | Latest |
| [LLVM](http://llvm.org/) | 8.0+|
| [Clang](http://clang.llvm.org/) | 8.0+ |
| [Intel XED](https://github.com/intelxed/xed) | Latest |
| [Python](https://www.python.org/) | 3.5.1+ |
| [IDA Pro](https://www.hex-rays.com/products/ida) | 7.1+ |
| [Binary Ninja](https://binary.ninja/) | Latest |

## Getting and Building the Code

### On Linux
First, update aptitude and get install the baseline dependencies.

```shell
sudo apt-get update
sudo apt-get upgrade

sudo apt-get install \
     git \
     python3 \
     python3-pip \
     wget \
     curl \
     build-essential \
     libtinfo-dev \
     lsb-release \
     zlib1g-dev \
     ccache

# Ubuntu 14.04, 16.04
sudo apt-get install realpath
```

The next step is to clone the Remill repository. We then clone the Anvill repository into the tools subdirectory of Remill. This is kind of like how Clang and LLVM are distributed separately, and the Clang source code needs to be put into LLVM's tools directory.

```shell
git clone https://github.com/lifting-bits/remill.git
cd remill/tools/
git clone https://github.com/lifting-bits/anvill.git
```

Finally, we build Remill along with Anvill. This script will create another directory, `remill-build`, in the current working directory. All remaining dependencies needed by Remill will be built in the `remill-build` directory.

```shell
cd ../../
./remill/scripts/build.sh
```

Anvill's python plugins provide functionality needed to generate a JSON specification that contains information about the contents of a binary.
These depend on tools like [IDA Pro](https://www.hex-rays.com/products/ida) or [Binary Ninja](https://binary.ninja/) for various analysis tasks.

Given that we have either of the above, we can try out Anvill's machine code lifter on a binary of our choice.

```shell
# First make sure we have the required python packages
pip3 install pyelftools
# Next we generate a JSON specification from a binary
python3 ./remill/tools/anvill/examples/lift.py --bin_in my_binary --spec_out spec.json
# Finally we produce LLVM bitcode from a JSON specification
./remill-build/tools/anvill/anvill-lift-json-*.0 --spec spec.json --bc_out out.bc
```

### Docker image

To build via Docker run, specify the architecture, base Ubuntu image and LLVM version. For example, to build Anvill linking against LLVM 9 on Ubuntu 20.04 on AMD64 do:

```shell
ARCH=amd64; DIST=ubuntu20.04; LLVM=900; \
   docker build . \
   -t anvill-llvm${LLVM}-${DIST}-${ARCH} \
   -f Dockerfile \
   --build-arg DISTRO_BASE=${DIST} \
   --build-arg ARCH=${ARCH} \
   --build-arg LLVM_VERSION=${LLVM}
```

## `anvill-specify-bitcode`

`anvill-specify-bitcode` is a tool that produces specifications for all functions
contained in an LLVM bitcode module. The purpose of this tool is to enable
the creation of a database of specifications for commonly used, often externally-
defined functions in binaries (e.g. libc, libc++, libstdc++) in binaries lifted
by [McSema](https://github.com/lifting-bits/mcsema).

This tool also exists for enabling function declarations for binary code to be
written in C or C++, and then translated down into the specification form within
a decompiler toolchain.

Finally, this tool exists to enable round-trip testing of LLVM's ISEL lowering
and code generation for arbitrary functions.
