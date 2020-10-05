#!/bin/bash

set -euo pipefail

python3 /opt/trailofbits/anvill/share/roundtrip.py \
  /opt/trailofbits/anvill/bin/anvill-decompile-json* \
  /opt/trailofbits/anvill/share/tests \
  $(which clang)
