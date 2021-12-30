#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_executable(test_anvill
  src/main.cpp
  src/Result.cpp
  src/TypeSpecification.cpp
)

target_link_libraries(test_anvill PRIVATE
  remill_settings
  remill
  anvill
  thirdparty_doctest
)

target_include_directories(test_anvill PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src"
)

add_test(
  NAME test_anvill
  COMMAND "$<TARGET_FILE:test_anvill>"
  WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
)
