#!/bin/bash

set -euo pipefail

CLANG=$(which clang)
CLANG_VERSION=$(${CLANG} --version)

echo "Running round-trip tests using: ${CLANG_VERSION}"
python3 /opt/trailofbits/anvill/share/roundtrip.py \
  /opt/trailofbits/anvill/bin/anvill-decompile-json* \
  /opt/trailofbits/anvill/share/tests \
  "${CLANG}"
