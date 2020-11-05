# Copyright (c) 2020 Trail of Bits, Inc.
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

enable_language(C CXX ASM)
macro(target_public_headers TARGET)
  set_target_properties(${TARGET} PROPERTIES PUBLIC_HEADER "${ARGN}")
endmacro()

option(ANVILL_INSTALL_PYTHON2_LIBS "Install Python 2 libraries")
option(ANVILL_INSTALL_PYTHON3_LIBS "Install Python 3 libraries" ON)

#
# libraries
#

# remill
if("${PLATFORM_NAME}" STREQUAL "windows")
  set(REMILL_FINDPACKAGE_HINTS HINTS "${CMAKE_INSTALL_PREFIX}/remill/lib")
endif()

find_package(remill REQUIRED ${REMILL_FINDPACKAGE_HINTS})

#
# target settings
#

set(ANVILL anvill-${REMILL_LLVM_VERSION})

add_subdirectory(lib/Version)

add_library(${ANVILL} STATIC
  include/anvill/Type.h

  lib/Arch/AArch64_C.cpp
  lib/Arch/SPARC32_C.cpp
  lib/Arch/SPARC64_C.cpp
  lib/Arch/X86_C.cpp
  lib/Arch/X86_FastCall.cpp
  lib/Arch/X86_StdCall.cpp
  lib/Arch/X86_ThisCall.cpp
  lib/Arch/X86_64_SysV.cpp
  
  lib/Arch/AllocationState.h
  lib/Arch/AllocationState.cpp
  
  lib/Arch/Arch.h
  lib/Arch/Arch.cpp
  
  include/anvill/TypeParser.h
  lib/TypeParser.cpp
  
  include/anvill/TypePrinter.h
  lib/TypePrinter.cpp
  
  include/anvill/Program.h
  lib/Program.cpp
  
  include/anvill/Decl.h
  lib/Decl.cpp
  
  include/anvill/Lift.h
  lib/Lift.cpp

  include/anvill/MCToIRLifter.h
  lib/MCToIRLifter.cpp

  include/anvill/Optimize.h
  lib/Optimize.cpp
  
  include/anvill/Analyze.h
  lib/Analyze.cpp
  
  include/anvill/Util.h
  lib/Util.cpp)

target_include_directories(${ANVILL} PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  ${PROJECT_INCLUDEDIRECTORIES})

target_link_libraries(${ANVILL} PUBLIC remill AnvillVersion)

target_public_headers(${ANVILL}
  include/anvill/Analyze.h
  include/anvill/Decl.h
  include/anvill/Lift.h
  include/anvill/Optimize.h
  include/anvill/Program.h
  include/anvill/Type.h
  include/anvill/TypeParser.h
  include/anvill/TypePrinter.h
  include/anvill/Version.h
  include/anvill/Util.h)

#
# tool target settings
#

set(DECOMPILE_JSON anvill-decompile-json-${REMILL_LLVM_VERSION})

add_executable(${DECOMPILE_JSON} bin/JSON.cpp)
target_link_libraries(${DECOMPILE_JSON} PRIVATE ${ANVILL})


set(SPECIFY_BITCODE anvill-specify-bitcode-${REMILL_LLVM_VERSION})

add_executable(${SPECIFY_BITCODE} bin/Bitcode.cpp)
target_link_libraries(${SPECIFY_BITCODE} PRIVATE ${ANVILL})

set(ANVILL_PYTHON_SOURCES
  setup.py
  python/anvill/__init__.py
  python/anvill/__main__.py
  python/anvill/arch.py
  python/anvill/binja.py
  python/anvill/exc.py
  python/anvill/function.py
  python/anvill/ida.py
  python/anvill/loc.py
  python/anvill/mem.py
  python/anvill/os.py
  python/anvill/program.py
  python/anvill/type.py
  python/anvill/var.py)

if(NOT DEFINED ENV{VIRTUAL_ENV})
  # NOT a venv install, specify --user and --prefix
  set(extra_install_flags --force --user --prefix=)
else()
  #virtual env; install normally
  set(extra_install_flags "")
endif()

if(ANVILL_INSTALL_PYTHON2_LIBS)
  add_custom_target(install_anvill_python2
    DEPENDS ${ANVILL_PYTHON_SOURCES})
    
  add_custom_command(
    TARGET install_anvill_python2 POST_BUILD
    COMMAND which python2 && python2 setup.py install ${extra_install_flags}
    COMMENT "Installing Anvill Python 2 API"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

  add_dependencies(${ANVILL}
    install_anvill_python2)
endif()

if(ANVILL_INSTALL_PYTHON3_LIBS)
  add_custom_target(install_anvill_python3
    DEPENDS ${ANVILL_PYTHON_SOURCES})

  add_custom_command(
    TARGET install_anvill_python3 POST_BUILD
    COMMAND which python3.8 && python3.8 setup.py install ${extra_install_flags}
    COMMENT "Installing Anvill Python 3 API"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

  add_dependencies(${ANVILL}
    install_anvill_python3)
endif()

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

set(ROUNDTRIP_TEST
  scripts/roundtrip.py)

install(
  FILES ${ROUNDTRIP_TEST}
  DESTINATION "${install_folder}/share")

#NOTE(artem): Uncomment and add tests as we pass them
set(ROUNDTRIP_TEST_FILES 
  #tests/assert.c
  #tests/bitops.c
  tests/cast.c
  #tests/funcptr.c
  #tests/nullptr.c
  tests/ret0.c
  #tests/zeroinit.c
)

install(
  FILES ${ROUNDTRIP_TEST_FILES}
  DESTINATION "${install_folder}/share/tests")

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/anvillConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/anvillConfig.cmake"
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/anvillConfig.cmake"
  DESTINATION "${install_folder}/lib/cmake/anvill"
)

#
# tests
#
# Note: the Binary Ninja or IDA Python API must exist to run tests.

enable_testing()

add_test(NAME test_roundtrip
  COMMAND ${PROJECT_SOURCE_DIR}/scripts/roundtrip.py $<TARGET_FILE:${DECOMPILE_JSON}> ${PROJECT_SOURCE_DIR}/tests ${CMAKE_C_COMPILER}
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
)
