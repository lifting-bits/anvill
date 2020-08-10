
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
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

FindAndSelectClangCompiler()

enable_language(C CXX ASM)
macro(target_public_headers TARGET)
  set_target_properties(${TARGET} PROPERTIES PUBLIC_HEADER "${ARGN}")
endmacro()

# warnings and compiler settings
if(NOT DEFINED WIN32)
  set(PROJECT_CXXFLAGS
    ${GLOBAL_CXXFLAGS} -Wconversion -pedantic
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

# llvm
find_package(LLVM REQUIRED CONFIG HINTS ${FINDPACKAGE_LLVM_HINTS})

string(REPLACE "." ";" LLVM_VERSION_LIST ${LLVM_PACKAGE_VERSION})
list(GET LLVM_VERSION_LIST 0 LLVM_MAJOR_VERSION)
list(GET LLVM_VERSION_LIST 1 LLVM_MINOR_VERSION)
set(REMILL_LLVM_VERSION "${LLVM_MAJOR_VERSION}.${LLVM_MINOR_VERSION}")

set(LLVM_LIBRARIES
  LLVMCore LLVMAnalysis LLVMSupport LLVMipo LLVMIRReader
  LLVMBitReader LLVMBitWriter LLVMTransformUtils LLVMScalarOpts
  LLVMLTO
)
list(APPEND PROJECT_LIBRARIES ${LLVM_LIBRARIES})
list(APPEND PROJECT_DEFINITIONS ${LLVM_DEFINITIONS})
list(APPEND PROJECT_INCLUDEDIRECTORIES ${LLVM_INCLUDE_DIRS})

# google log module
find_package(glog REQUIRED)
list(APPEND PROJECT_LIBRARIES glog::glog)

# gflags
find_package(gflags REQUIRED)
list(APPEND PROJECT_LIBRARIES gflags)

# xed
find_package(XED REQUIRED)
list(APPEND PROJECT_LIBRARIES ${XED_LIBRARIES})
list(APPEND PROJECT_INCLUDEDIRECTORIES ${XED_INCLUDE_DIRS})

# z3
if (LLVM_Z3_INSTALL_DIR)
  find_package(Z3 4.7.1)
  set(need_z3 TRUE)
elseif(DEFINED ENV{TRAILOFBITS_LIBRARIES})
  set(LLVM_Z3_INSTALL_DIR "$ENV{TRAILOFBITS_LIBRARIES}/z3")
  set(need_z3 TRUE)
else()
  set(need_z3 FALSE)
endif()

if(need_z3)
  find_package(Z3 4.7.1)
  if (NOT Z3_FOUND)
    message(WARNING "Z3 >= 4.7.1 has not been found in LLVM_Z3_INSTALL_DIR: ${LLVM_Z3_INSTALL_DIR}.")
  endif()
  list(APPEND PROJECT_LIBRARIES Z3)
endif()


#
# target settings
#

set(ANVILL anvill-${REMILL_LLVM_VERSION})

add_subdirectory(lib/Version)

add_library(${ANVILL} STATIC
    include/anvill/Type.h

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
    
    include/anvill/Optimize.h
    lib/Optimize.cpp
    
    include/anvill/Analyze.h
    lib/Analyze.cpp)

target_compile_definitions(${ANVILL} PUBLIC
    ${PROJECT_DEFINITIONS})

target_compile_options(${ANVILL} PUBLIC
    ${PROJECT_CXXFLAGS})

target_include_directories(${ANVILL} PUBLIC
   "${CMAKE_CURRENT_SOURCE_DIR}/include"
   ${PROJECT_INCLUDEDIRECTORIES})

target_link_libraries(${ANVILL} PUBLIC remill ${PROJECT_LIBRARIES} AnvillVersion)

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
  )

#
# tool target settings
#

set(DECOMPILE_JSON anvill-decompile-json-${REMILL_LLVM_VERSION})

add_executable(${DECOMPILE_JSON} JSON.cpp)
target_link_libraries(${DECOMPILE_JSON} PRIVATE ${ANVILL})


set(SPECIFY_BITCODE anvill-specify-bitcode-${REMILL_LLVM_VERSION})

add_executable(${SPECIFY_BITCODE} Bitcode.cpp)
target_link_libraries(${SPECIFY_BITCODE} PRIVATE ${ANVILL})


add_custom_target(install_anvill_python
  DEPENDS
  setup.py
  python/anvill/__init__.py
  python/anvill/arch.py
  python/anvill/binja.py
  python/anvill/dwarf.py
  python/anvill/exc.py
  python/anvill/function.py
  python/anvill/ida.py
  python/anvill/loc.py
  python/anvill/mem.py
  python/anvill/os.py
  python/anvill/program.py
  python/anvill/type.py
  python/anvill/var.py)

add_custom_command(
    TARGET install_anvill_python POST_BUILD
    COMMAND which python2 && python2 setup.py install --force --user --prefix=
    COMMENT "Installing Anvill Python 2.7 API"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

add_custom_command(
    TARGET install_anvill_python POST_BUILD
    COMMAND which python3 && python3 setup.py install --force --user --prefix=
    COMMENT "Installing Anvill Python 3 API"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

add_dependencies(${ANVILL}
  install_anvill_python)

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

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/anvillConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/anvillConfig.cmake"
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/anvillConfig.cmake"
    DESTINATION "${install_folder}/lib/cmake/anvill"
)
