# Anvill

Anvill implements simple machine code lifting primitives using Remill.
The goal of these components is to produce high quality bitcode,
which can then be further decompiled to C (via Clang ASTs) using
[Rellic](https://github.com/lifting-bits/rellic.git).

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

Anvill is supported on Linux platforms and has been tested on Ubuntu 20.04.

## Dependencies

Most of Anvill's dependencies can be provided by the [cxx-common](https://github.com/lifting-bits/cxx-common) repository. Trail of Bits hosts downloadable, pre-built versions of the libraries for select operating systems, which makes it substantially easier to get up and running with Anvill. Nonetheless, the following table represents most of Anvill's dependencies.

| Name | Version |
| ---- | ------- |
| [Git](https://git-scm.com/) | Latest |
| [CMake](https://cmake.org/) | 3.14+ |
| [Clang](http://clang.llvm.org/) | 12.0+|
| [Remill](https://github.com/lifting-bits/remill) | Latest |
| [Python](https://www.python.org/) | 3.9 |
| [IDA Pro](https://www.hex-rays.com/products/ida) | 7.5+ |
| [Binary Ninja](https://binary.ninja/) | Latest |

## Getting and Building the Code

### On Linux
First, update aptitude and get install the baseline dependencies.

```shell
dpkg --add-architecture i386

sudo apt-get update
sudo apt-get upgrade

sudo apt-get install \
     git \
     python3.8 \
     python3-pip \
     wget \
     curl \
     build-essential \
     libtinfo-dev \
     lsb-release \
     zlib1g-dev \
     ccache \
     cmake \
     libc6-dev:i386 \
     'libstdc++-*-dev:i386' \
     g++-multilib

# Ubuntu 14.04, 16.04
sudo apt-get install realpath
```

Assuming we have [Remill](https://github.com/lifting-bits/remill) properly installed the following steps provide a fresh build of Anvill.

```shell
# clone anvill repository
git clone https://github.com/lifting-bits/anvill.git

# update the git submodules
git submodule update --init --recursive

# create a build dir
mkdir anvill-build && cd anvill-build

# configure
CC=clang cmake ../anvill

# build
make -j 5

# install
sudo make install
```

Or you can tell CMake where to find the remill installation prefix by passing `-Dremill_DIR="<remill_prefix>/lib/cmake/remill"` during configuration.

Anvill's python plugins provide functionality needed to generate a JSON specification that contains information about the contents of a binary.
These depend on tools like [IDA Pro](https://www.hex-rays.com/products/ida) or [Binary Ninja](https://binary.ninja/) for various analysis tasks.

Given that we have either of the above, we can try out Anvill's machine code lifter on a binary of our choice.

**First, we generate a JSON specification from a binary:**

From the CLI:

```shell
python3 -m anvill --bin_in my_binary --spec_out spec.json
```

With the IDA plugin:
1. Open the binary inside IDA
2. Select **Run script** in the **File** menu
3. Open the `anvill/plugins/ida/anvill.py`
4. In the disasm window, place the cursor inside a function
5. Right click and select **Generate ANVILL spec file**

**Finally we produce LLVM bitcode from a JSON specification**

```
./build/anvill-decompile-json-*.0 --spec spec.json --bc_out out.bc
```

### Running tests

1. Configure with the following parameter: `-DANVILL_ENABLE_TESTS=true`
2. Run the **test** target: `cmake --build build_folder --target test`

### Docker image

To build via Docker run, specify the architecture, base Ubuntu image and LLVM version. For example, to build Anvill linking against LLVM 12 on Ubuntu 20.04 on AMD64 do:

```shell
ARCH=amd64; UBUNTU_VERSION=20.04; LLVM=12; \
   docker build . \
   -t anvill-llvm${LLVM}-ubuntu${UBUNTU_VERSION}-${ARCH} \
   -f Dockerfile \
   --build-arg UBUNTU_VERSION=${UBUNTU_VERSION} \
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
