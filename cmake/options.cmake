#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Build type")

option(ANVILL_ENABLE_INSTALL_TARGET "Set to ON to enable the install directives. This installs both the native and python components" true)
option(ANVILL_ENABLE_TESTS "Set to ON to enable the tests" true)
option(ANVILL_INSTALL_PYTHON3_LIBS "Install Python 3 libraries to the **local machine** at build time. Mostly used for local development, not required for packaging")

set(VCPKG_ROOT "" CACHE FILEPATH "Root directory to use for vcpkg-managed dependencies")
