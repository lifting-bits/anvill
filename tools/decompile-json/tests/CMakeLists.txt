#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_test(NAME test_roundtrip
  COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/scripts/roundtrip.py" "$<TARGET_FILE:anvill-decompile-json>" "${CMAKE_CURRENT_SOURCE_DIR}/samples" "${CMAKE_C_COMPILER}"
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)
