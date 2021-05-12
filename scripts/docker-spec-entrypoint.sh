#!/usr/bin/env bash

#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

# Needed to process multiple arguments to docker image and source venv

source "${VIRTUAL_ENV}/bin/activate"

python3 -m anvill "$@"
