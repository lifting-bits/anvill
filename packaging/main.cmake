#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
  set(CPACK_GENERATOR "TGZ;DEB;RPM")

elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
  set(CPACK_GENERATOR "TGZ")
endif()

if(ANVILL_DATA_PATH STREQUAL "")
  message(FATAL_ERROR "The ANVILL_DATA_PATH variable was not set")
endif()

if(ANVILL_PACKAGE_VERSION STREQUAL "")
  message(FATAL_ERROR "The ANVILL_PACKAGE_VERSION variable was not set")
endif()

set(CPACK_PROJECT_CONFIG_FILE "${CMAKE_CURRENT_LIST_DIR}/cmake/dispatcher.cmake")

set(CPACK_PACKAGE_DESCRIPTION "anvill forges beautiful LLVM bitcode out of raw machine code")
set(CPACK_PACKAGE_NAME "anvill")
set(CPACK_PACKAGE_VENDOR "Trail of Bits")
set(CPACK_PACKAGE_CONTACT "opensource@trailofbits.com")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/lifting-bits/anvill")
