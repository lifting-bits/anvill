#!/bin/bash

#These are filled in by the CI system
export ANVILL_BRANCH=__ANVILL_BRANCH__
export RUN_SIZE=__RUN_SIZE__
export BINJA_DECODE_KEY=__BINJA_DECODE_KEY__
export BINJA_CHANNEL=__BINJA_CHANNEL__
export BINJA_VERSION=__BINJA_VERSION__

export LLVM_VERSION=13
export CC=clang-13 CXX=clang++-13

dpkg --add-architecture i386
apt-get update
apt-get install -yqq s3cmd pixz curl git python3 python3-venv python3-pip xz-utils cmake ninja-build clang-13 g++-multilib unzip
apt-get install -yqq libc6-dev:i386 libstdc++-*-dev:i386
python3 -m pip install requests

#install new cmake
curl -LO https://github.com/Kitware/CMake/releases/download/v3.22.1/cmake-3.22.1-linux-x86_64.sh
sh ./cmake-3.22.1-linux-x86_64.sh --skip-license --prefix=/usr

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

# Should be installed by build.sh --isntall, but sometimes the script accidentally breaks venv installs
python3 setup.py install

# install binja
ci/install_binja.sh
python3 ci/switcher.py --version ${BINJA_VERSION} ${BINJA_CHANNEL}
popd

pushd ci

# Install extra requirements if needed
if [[ -f requirements.txt ]]
then
    python3 -m pip install -r requirements.txt
fi

mkdir -p $(pwd)/anvill_bitcode

# default to 1k
if [[ "${RUN_SIZE,,}" = "__run_size__" ]]
then
   RUN_SIZE=1k
fi

datasets/fetch_anghabench.sh --clang ${LLVM_VERSION} --binaries --run-size ${RUN_SIZE}

for i in *.tar.xz
do
    tar -xJf $i
done

# Run the benchmark
tool_run_scripts/anvill.py \
    --run-name "[${RUN_NAME}] [size: ${RUN_SIZE}] [anvill: ${ANVILL_BRANCH}]" \
    --input-dir $(pwd)/binaries \
    --output-dir $(pwd)/anvill_bitcode \
    --anvill-decompile /usr/local/bin/anvill-decompile-json \
    --slack-notify

# AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY passed in from original invocation environment
if [[ "${AWS_ACCESS_KEY_ID,,}" != "" ]]
then
    datenow=$(date +'%F-%H-%M')
    url_base="https://tob-amp-ci-results.nyc3.digitaloceanspaces.com"
    tar -Ipixz -cf anvill-ci-${datenow}.tar.xz anvill_bitcode

    s3cmd -c /dev/null \
        '--host-bucket=%(bucket)s.nyc3.digitaloceanspaces.com' \
        --acl-public \
        put \
        anvill-ci-${datenow}.tar.xz \
        s3://tob-amp-ci-results/anvill/

    tool_run_scripts/slack.py \
        --msg "Uploaded Anvill lifting results to ${url_base}/anvill/anvill-ci-${datenow}.tar.xz"
fi

# exit hook called here
exit 0
