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

INSTALL_PREFIX=/opt/trailofbits/anvill
if [ -d "${INSTALL_PREFIX}" ] ; then
  # Old installation tree
  echo "Running round-trip tests using: ${CLANG_VERSION}"
  python3.8 "${INSTALL_PREFIX}/share/roundtrip.py" \
    "${INSTALL_PREFIX}/bin/anvill-decompile-json-${V}.0" \
    "${INSTALL_PREFIX}/share/tests" \
    "${CLANG}"
else
  INSTALL_PREFIX="/usr/local"
  echo "Running round-trip tests using: ${CLANG_VERSION}"
  python3.8 "${INSTALL_PREFIX}/share/anvill/roundtrip.py" \
    "${INSTALL_PREFIX}/bin/anvill-decompile-json-${V}.0" \
    "${INSTALL_PREFIX}/share/anvill/tests" \
    "${CLANG}"
fi
