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

CLANG=$(which clang-${V})
CLANG_VERSION=$(${CLANG} --version)

echo "Running round-trip tests using: ${CLANG_VERSION}"
python3.8 /opt/trailofbits/anvill/share/roundtrip.py \
  /opt/trailofbits/anvill/bin/anvill-decompile-json* \
  /opt/trailofbits/anvill/share/tests \
  "${CLANG}"
