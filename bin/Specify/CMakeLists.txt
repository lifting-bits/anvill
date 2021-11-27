#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_executable(anvill-specify-bitcode
  Main.cpp
)

target_link_libraries(anvill-specify-bitcode PRIVATE
  anvill
)

if(ANVILL_ENABLE_INSTALL_TARGET)
  install(
    TARGETS
      anvill-specify-bitcode

    EXPORT
      anvillTargets

    RUNTIME DESTINATION
      bin
  )
endif()
