#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_executable(anvill-decompile-json
  src/ControlFlowProvider.cpp
  src/ControlFlowProvider.h
  src/Main.cpp
  src/MemoryProvider.cpp
  src/MemoryProvider.h
  src/Program.cpp
  src/Program.h
  src/TypeProvider.cpp
  src/TypeProvider.h
)

target_link_libraries(anvill-decompile-json PRIVATE
  anvill
  thirdparty_magicenum
)

if(ANVILL_ENABLE_TESTS)
  add_subdirectory("tests")
endif()

if(ANVILL_ENABLE_INSTALL_TARGET)
  install(
    TARGETS
      anvill-decompile-json

    EXPORT
      anvillTargets

    RUNTIME DESTINATION
      bin
  )
endif()
