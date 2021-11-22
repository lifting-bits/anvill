#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

if(VCPKG_ROOT)
  message(WARNING "Building with VCPKG")
  include(cmake/vcpkg_helper.cmake)
endif()

project(anvill)
cmake_minimum_required(VERSION 3.14)

include("cmake/options.cmake")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT VCPKG_ROOT)
  message(WARNING "Running the standard CMake build; if this is a mistake, reconfigure again and pass `-DVCPKG_ROOT=/path/to/vcpkg`")
  include(cmake/system_build.cmake)
else()
  find_package(remill CONFIG REQUIRED)
endif()

include("cmake/utils.cmake")

include(GNUInstallDirs)

if(ANVILL_ENABLE_TESTS)
  message(STATUS "anvill: Tests have been enabled")
  enable_testing()
else()
  message(STATUS "anvill: Tests are not enabled")
endif()

FindAndSelectClangCompiler()

find_program(ccache_path ccache)
if("${ccache_path}" STREQUAL "ccache_path-NOTFOUND")
  message(STATUS "anvill: ccache was not found")

else()
  message(STATUS "anvill: Enabling ccache support with ${ccache_path}")

  set(CMAKE_CXX_COMPILER_LAUNCHER "${ccache_path}" CACHE FILEPATH "")
  set(CMAKE_C_COMPILER_LAUNCHER "${ccache_path}" CACHE FILEPATH "")
endif()

add_subdirectory("libraries")
add_subdirectory("lib")
add_subdirectory("bin")

if(ANVILL_ENABLE_SANITIZERS)
  configureSanitizers("remill_settings")
endif(ANVILL_ENABLE_SANITIZERS)

if(ANVILL_ENABLE_INSTALL_TARGET)

  set(anvill_cmake_config
    "${CMAKE_CURRENT_BINARY_DIR}/anvillConfig.cmake"
  )

  configure_file(
    "${PROJECT_SOURCE_DIR}/cmake/anvillConfig.cmake.in"
    "${anvill_cmake_config}"
    @ONLY
  )
  
  install(FILES "${anvill_cmake_config}"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/anvill"
  )
  
  install(EXPORT anvillTargets
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/anvill"
  )

  install(DIRECTORY "${CMAKE_SOURCE_DIR}/anvill/include/anvill/"
    DESTINATION "include/anvill" FILES_MATCHING PATTERN "*.h"
   )

endif(ANVILL_ENABLE_INSTALL_TARGET)