#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

# Find remill first because its config has useful dependency-finding info that
# needs to be found before the CMake `project` declaration
find_package(remill COMPONENTS VCPKG_DEPS QUIET)
include(cmake/vcpkg_helper.cmake)

project(anvill)
cmake_minimum_required(VERSION 3.14)

include("cmake/options.cmake")
include("cmake/settings.cmake")
include("cmake/utils.cmake")

include(GNUInstallDirs)

if(ANVILL_ENABLE_TESTS)
  enable_testing()
endif()

FindAndSelectClangCompiler()

find_package(remill CONFIG REQUIRED)

add_subdirectory("libraries")
add_subdirectory("tools")
add_subdirectory("anvill")
