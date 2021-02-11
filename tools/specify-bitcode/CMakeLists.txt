#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_executable(anvill-specify-bitcode
  src/main.cpp
)

target_link_libraries(anvill-specify-bitcode PRIVATE
  anvill
)

appendRemillVersionToTargetOutputName(anvill-specify-bitcode)
