#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.19)

include("cmake/options.cmake")
include("cmake/ccache.cmake")
include("cmake/vcpkg_helper.cmake")

project("anvill")

include(GNUInstallDirs)
include("cmake/system.cmake")

if(ANVILL_ENABLE_INSTALL)
  include("cmake/packaging.cmake")
endif(ANVILL_ENABLE_INSTALL)

add_subdirectory("libraries")

set(_VCPKG_SHARE_DIR "${VCPKG_ROOT}/installed/${VCPKG_TARGET_TRIPLET}/${CMAKE_INSTALL_DATADIR}")

find_package(XED CONFIG REQUIRED HINTS "${_VCPKG_SHARE_DIR}")
find_package(gflags CONFIG REQUIRED HINTS "${_VCPKG_SHARE_DIR}")
find_package(glog CONFIG REQUIRED HINTS "${_VCPKG_SHARE_DIR}")
find_package(Z3 4.8 CONFIG REQUIRED)
find_package(doctest CONFIG REQUIRED HINTS "${_VCPKG_SHARE_DIR}")
find_package(LLVM CONFIG REQUIRED HINTS "${_VCPKG_SHARE_DIR}")
llvm_map_components_to_libnames(llvm_libs support core irreader bitreader bitwriter)

find_package(sleigh CONFIG)
find_package(remill CONFIG REQUIRED)

if(ANVILL_ENABLE_INSTALL)
  export(PACKAGE "${PROJECT_NAME}")

  set(cmake_install_dir "lib/cmake/${PROJECT_NAME}")

  include(CMakePackageConfigHelpers)
  configure_package_config_file("${PROJECT_NAME}Config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    INSTALL_DESTINATION "${cmake_install_dir}"
  )

  install(
    FILES
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    DESTINATION "${cmake_install_dir}"
  )
  install(EXPORT "${PROJECT_NAME}Targets"
    DESTINATION "${cmake_install_dir}"
    NAMESPACE "${PROJECT_NAME}::"
  )
endif(ANVILL_ENABLE_INSTALL)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)

if(ANVILL_ENABLE_TESTS)
  message(STATUS "anvill: Tests have been enabled")
  enable_testing()
else()
  message(STATUS "anvill: Tests are not enabled")
endif(ANVILL_ENABLE_TESTS)

add_subdirectory("lib")
add_subdirectory("bin")

if(ANVILL_ENABLE_TESTS)
  add_subdirectory("tests")
endif()
