#!/bin/bash

#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

# This script is run inside Github Actions CI to create an archive of a fully-built project

# install pixz for parallel xz
DEBIAN_FRONTEND=noninteractive apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -yqq pixz
# compress /opt/trailofbits/{anvill,remill} and emit it to $1
echo "Compressing to: ${1}"
tar -Ipixz -cf "${1}" -C /opt/trailofbits anvill remill 
