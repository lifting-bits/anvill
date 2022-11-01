#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_executable(anvill-decompile-spec
  "Main.cpp"
)

set_target_properties(anvill-decompile-spec
  PROPERTIES
  LINKER_LANGUAGE CXX
)

target_link_libraries(anvill-decompile-spec PRIVATE
  anvill
)

# if(ANVILL_ENABLE_TESTS)
# add_subdirectory("tests")
# endif(ANVILL_ENABLE_TESTS)
if(ANVILL_ENABLE_INSTALL)
  install(
    TARGETS
    anvill-decompile-spec

    EXPORT
    anvillTargets

    RUNTIME DESTINATION
    bin
  )
endif(ANVILL_ENABLE_INSTALL)
