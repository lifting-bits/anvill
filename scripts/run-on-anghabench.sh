#!/bin/bash

#These are filled in by the CI system
export ANVILL_BRANCH=__ANVILL_BRANCH__
export RUN_SIZE=__RUN_SIZE__
export BINJA_DECODE_KEY=__BINJA_DECODE_KEY__

export LLVM_VERSION=11
export CC=clang-11 CXX=clang++-11

dpkg --add-architecture i386
apt-get update
apt-get install -yqq curl git python3 python3-venv python3-pip xz-utils cmake ninja-build clang-11 g++-multilib unzip
apt-get install -yqq libc6-dev:i386 libstdc++-*-dev:i386
python3 -m pip install requests

git clone --recursive --shallow-submodules --depth=1 -b ${ANVILL_BRANCH}  https://github.com/lifting-bits/anvill anvill
# CI Branch is defined by the CI system
git clone --recursive --shallow-submodules --depth=1 -b ${CI_BRANCH} https://github.com/lifting-bits/lifting-tools-ci ci

python3 -m venv anvill-venv
source anvill-venv/bin/activate

pushd anvill
# build us an anvill (and remill)
scripts/build.sh \
    --install \
    --llvm-version ${LLVM_VERSION} \
    --extra-cmake-args "-DCMAKE_BUILD_TYPE=Release"

# install binja
ci/install_binja.sh
popd

pushd ci

# Install extra requirements if needed
if [[ -f requirements.txt ]]
then
    python3 -m pip install -r requirements.txt
fi

mkdir -p $(pwd)/output

# default to 1k
if [[ "${RUN_SIZE,,}" = "__run_size__" ]]
then
   RUN_SIZE=1k
fi

datasets/fetch_anghabench.sh --binaries --run-size ${RUN_SIZE}

for i in *.tar.xz
do
    tar -xJf $i
done

# Run the benchmark
tool_run_scripts/anvill.py \
    --run-name "[${RUN_NAME}] [size: ${RUN_SIZE}] [anvill: ${ANVILL_BRANCH}]" \
    --input-dir $(pwd)/binaries \
    --output-dir $(pwd)/output \
    --anvill-decompile /usr/local/bin/anvill-decompile-json-${LLVM_VERSION}.0
    --slack-notify

# exit hook called here
exit 0