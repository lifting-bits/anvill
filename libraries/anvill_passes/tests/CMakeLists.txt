#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_executable(test_anvil_passes
  src/main.cpp

  src/Utils.h
  src/Utils.cpp

  src/BaseScenario.h
  src/BaseScenario.cpp

  src/RecoverStackFrameInformation.cpp
  src/SplitStackFrameAtReturnAddress.cpp
)

target_link_libraries(test_anvil_passes PRIVATE
  remill_settings
  remill
  anvill_passes
  thirdparty_doctest
)

target_compile_definitions(test_anvil_passes PRIVATE
  ANVILL_TEST_DATA_PATH=\"${CMAKE_CURRENT_SOURCE_DIR}/data\"
)

target_include_directories(test_anvil_passes PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src"
)

add_test(
  NAME test_anvil_passes
  COMMAND "$<TARGET_FILE:test_anvil_passes>"
  WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
)
