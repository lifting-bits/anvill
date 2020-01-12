
# Copyright (c) 2019 Trail of Bits, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

project(anvill)
cmake_minimum_required(VERSION 3.2)

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/settings.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/utils.cmake")

FindAndSelectClangCompiler()

# warnings and compiler settings
if(NOT DEFINED WIN32)
  set(PROJECT_CXXFLAGS
    ${GLOBAL_CXXFLAGS} -Werror -Wconversion -pedantic 
    -Wno-unreachable-code-return 
  )
endif()

#
# libraries
#

# remill
if(NOT TARGET remill)
  if("${PLATFORM_NAME}" STREQUAL "windows")
    set(REMILL_FINDPACKAGE_HINTS HINTS "${CMAKE_INSTALL_PREFIX}/remill/lib")
  endif()

  find_package(remill REQUIRED ${REMILL_FINDPACKAGE_HINTS})
endif()

#
# target settings
#

set(ANVILL anvill-${REMILL_LLVM_VERSION})

add_library(${ANVILL} STATIC
    include/anvill/Decl.h
    include/anvill/Program.h
    include/anvill/Type.h
    include/anvill/Arch.h
    include/anvill/TypeParser.h
    include/anvill/TypePrinter.h

    lib/Arch.cpp
    lib/TypeParser.cpp
    lib/TypePrinter.cpp
    lib/Program.cpp lib/Decl.cpp include/anvill/Lift.h lib/Lift.cpp lib/Lift.h include/anvill/Optimize.h lib/Optimize.cpp include/anvill/Analyze.h lib/Analyze.cpp)

target_compile_definitions(${ANVILL} PUBLIC
    ${PROJECT_DEFINITIONS})

target_compile_options(${ANVILL} PUBLIC
    ${PROJECT_CXXFLAGS})

target_include_directories(${ANVILL} PUBLIC
   "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_link_libraries(${ANVILL} PUBLIC remill)

#
# tool target settings
#

set(DECOMPILE_JSON anvill-decompile-json-${REMILL_LLVM_VERSION})

add_executable(${DECOMPILE_JSON} JSON.cpp)
target_link_libraries(${DECOMPILE_JSON} PRIVATE ${ANVILL})


set(SPECIFY_BITCODE anvill-specify-bitcode-${REMILL_LLVM_VERSION})

add_executable(${SPECIFY_BITCODE} BITCODE.cpp)
target_link_libraries(${SPECIFY_BITCODE} PRIVATE ${ANVILL})

#
# install settings
#

if(DEFINED WIN32)
  set(install_folder "${CMAKE_INSTALL_PREFIX}/anvill")
else()
  set(install_folder "${CMAKE_INSTALL_PREFIX}")
endif()

install(
    TARGETS ${ANVILL}
    LIBRARY DESTINATION "${install_folder}/lib"
    PUBLIC_HEADER DESTINATION "${install_folder}/include/anvill")

install(
    TARGETS ${DECOMPILE_JSON}
    RUNTIME DESTINATION "${install_folder}/bin")
