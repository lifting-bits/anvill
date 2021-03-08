#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_library(thirdparty_magicenum INTERFACE)
target_include_directories(thirdparty_magicenum INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/src/include"
)

# TODO: We can switch to target_link_libraries if we update to
# a more up-to-date CMake version and change the cmake_minimum_required.
#
# This will let us link against this INTERFACE target without requiring
# us to export it
function(addMagicEnumLibrary target_name)
  target_include_directories("${target_name}" PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/../magic_enum/src/include"
  )
endfunction()
