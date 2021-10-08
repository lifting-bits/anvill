#!/bin/sh

#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

# Needed to process multiple arguments to docker image

V=""
case ${LLVM_VERSION} in
  llvm12*)
    V=12
  ;;
  *)
    echo "Unknown or unsuppoted LLVM version: ${LLVM_VERSION}"
    exit 1
  ;;
esac

anvill-decompile-json-${V} "$@"
