#!/bin/bash

set -euo pipefail

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


apt-get update &> /dev/null
apt-get install -qqy clang-${V} &> /dev/null
