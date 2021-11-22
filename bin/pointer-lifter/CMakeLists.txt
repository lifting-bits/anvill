#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_executable(pointer-lifter
  src/main.cpp
)

target_link_libraries(pointer-lifter PRIVATE
  anvill
)

if(ANVILL_ENABLE_TESTS)
  add_subdirectory("tests")
endif()

if(ANVILL_ENABLE_INSTALL_TARGET)
  install(
    TARGETS
      pointer-lifter

    EXPORT
      anvillTargets

    RUNTIME DESTINATION
      bin
  )
endif()
