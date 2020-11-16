#!/bin/bash

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

V=""
case ${LLVM_VERSION} in
  llvm80*)
    V=8
  ;;
  llvm90*)
    V=9
  ;;
  llvm100*)
    V=10
  ;;
  llvm110*)
    V=11
  ;;
  *)
    echo "Unknown or unsupported LLVM version: ${LLVM_VERSION}"
    exit 1
  ;;
esac

function install_from_llvm() {
    echo "Could not install default clang-${V}"
    echo "Attempting to install it from LLVM apt repo"
    apt-get install -qqy lsb-release wget software-properties-common &>/dev/null
    wget https://apt.llvm.org/llvm.sh
    chmod +x ./llvm.sh
    ./llvm.sh ${V}
    rm -f llvm.sh
}

apt-get update &> /dev/null
apt-get install -qqy clang-${V} &> /dev/null || install_from_llvm
