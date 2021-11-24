#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_executable(anvill-decompile-json
  "ControlFlowProvider.cpp"
  "ControlFlowProvider.h"
  "Main.cpp"
  "MemoryProvider.cpp"
  "MemoryProvider.h"
  "Program.cpp"
  "Program.h"
  "TypeProvider.cpp"
  "TypeProvider.h"
)

set_target_properties(anvill-decompile-json
  PROPERTIES
    LINKER_LANGUAGE CXX
)

target_link_libraries(anvill-decompile-json PRIVATE
  anvill
)

#if(ANVILL_ENABLE_TESTS)
#  add_subdirectory("tests")
#endif(ANVILL_ENABLE_TESTS)

if(ANVILL_ENABLE_INSTALL_TARGET)
  install(
    TARGETS
      anvill-decompile-json

    EXPORT
      anvillTargets

    RUNTIME DESTINATION
      bin
  )
endif(ANVILL_ENABLE_INSTALL_TARGET)
