#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

include(CMakeDependentOption)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set(default_build_type "Release")
else()
  set(default_build_type "RelWithDebInfo")
endif()

set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Build type")

option(ANVILL_ENABLE_INSTALL_TARGET "Set to ON to enable the install directives. This installs both the native and python components" true)
option(ANVILL_ENABLE_PYTHON3_LIBS "Build Python 3 libraries" ON)
option(ANVILL_ENABLE_TESTS "Set to ON to enable the tests" true)
cmake_dependent_option(ANVILL_INSTALL_PYTHON3_LIBS "Install Python 3 libraries to the **local machine** at build time. Mostly used for local development, not required for packaging" OFF
  "NOT ANVILL_ENABLE_PYTHON3_LIBS OR NOT ANVILL_ENABLE_INSTALL_TARGET" OFF
  )
option(ANVILL_ENABLE_SANITIZERS "Set to ON to enable sanitizers. May not work with VCPKG")

set(VCPKG_ROOT "" CACHE FILEPATH "Root directory to use for vcpkg-managed dependencies")

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX "/usr" CACHE PATH "Install prefix (forced)" FORCE)
endif()
