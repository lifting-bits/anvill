# Copyright (c) 2020-presente Trail of Bits, Inc.
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

# Find remill first because its config has useful dependency-finding info that
# needs to be found before the CMake `project` declaration
find_package(remill COMPONENTS VCPKG_DEPS QUIET)

include(cmake/vcpkg_helper.cmake)
include(cmake/options.cmake)

project(anvill)

if(ANVILL_ENABLE_TESTS)
  enable_testing()
endif()

cmake_minimum_required(VERSION 3.14)
include(GNUInstallDirs)
enable_language(C CXX ASM)

include("cmake/settings.cmake")
include("cmake/utils.cmake")

FindAndSelectClangCompiler()

macro(target_public_headers TARGET)
  set_target_properties(${TARGET} PROPERTIES PUBLIC_HEADER "${ARGN}")
endmacro()

option(ANVILL_INSTALL_PYTHON3_LIBS "Install Python 3 libraries" ON)

#
# libraries
#
find_package(remill CONFIG REQUIRED)

#
# target settings
#

add_subdirectory(lib/Version)
add_subdirectory("tools")

add_library(anvill STATIC
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
  
  include/anvill/RecoverMemRefs.h
  lib/RecoverMemRefs.cpp

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

appendRemillVersionToTargetOutputName(anvill)

target_include_directories(anvill PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
  )

target_link_libraries(anvill PUBLIC remill_settings remill AnvillVersion)

target_public_headers(anvill
  include/anvill/Analyze.h
  include/anvill/Decl.h
  include/anvill/Lift.h
  include/anvill/Optimize.h
  include/anvill/Program.h
  include/anvill/RecoverMemRefs.h
  include/anvill/Type.h
  include/anvill/TypeParser.h
  include/anvill/TypePrinter.h
  include/anvill/Version.h
  include/anvill/Util.h)

#
# tool target settings
#


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

  add_dependencies(anvill
    install_anvill_python2)
endif()

if(ANVILL_INSTALL_PYTHON3_LIBS)
  add_custom_target(install_anvill_python3
    DEPENDS ${ANVILL_PYTHON_SOURCES})

  add_custom_command(
    TARGET install_anvill_python3 POST_BUILD
    COMMAND which python3 && python3 setup.py install ${extra_install_flags}
    COMMENT "Installing Anvill Python 3 API"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

  add_dependencies(anvill
    install_anvill_python3)
endif()

set(ROUNDTRIP_TEST
  scripts/roundtrip.py)

install(
  FILES ${ROUNDTRIP_TEST}
  DESTINATION "${CMAKE_INSTALL_DATADIR}/anvill")

#NOTE(artem): Uncomment and add tests as we pass them
set(ROUNDTRIP_TEST_FILES
  tests/array_swap.c
  # tests/assert.c
  tests/binops.c
  tests/bitops.c
  # tests/branch.c
  tests/cast.c
  # tests/funcptr.c
  tests/init_list.c
  tests/inttoptr.c
  # tests/loop.c
  # tests/nested_struct.c
  tests/nullptr.c
  tests/ret0.c
  tests/struct_swap.c
  tests/struct.c
  # tests/sum.c
  tests/trunc.c
  tests/zeroinit.c
  tests/zext.c
  # tests/binja_var_none_type.c
)

install(
  FILES ${ROUNDTRIP_TEST_FILES}
  DESTINATION "${CMAKE_INSTALL_DATADIR}/anvill/tests")

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/anvillConfig_vcpkg.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/anvillConfig.cmake"
  @ONLY
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/anvillConfig.cmake"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/anvill"
)

install(EXPORT anvillTargets
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/anvill")

#
# tests
#
# Note: the Binary Ninja or IDA Python API must exist to run tests.

function(generateAnvillInstallTarget)
  if(NOT ANVILL_ENABLE_INSTALL_TARGET)
    return()
  endif()

  # Depending on the LLVM version used, some targets may not
  # be available
  set(install_target_list
    anvill
  )

  if(TARGET anvill-decompile-json)
    list(APPEND install_target_list
      anvill-decompile-json
    )
  endif()

  if(TARGET anvill-specify-bitcode)
    list(APPEND install_target_list
      anvill-specify-bitcode
    )
  endif()

  install(
    TARGETS
      ${install_target_list}

    EXPORT
      anvillTargets

    LIBRARY DESTINATION
      lib

    ARCHIVE DESTINATION
      lib

    RUNTIME DESTINATION
      bin

    INCLUDES DESTINATION
      include
  )
endfunction()

generateAnvillInstallTarget()
