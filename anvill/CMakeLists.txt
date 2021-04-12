#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

set(public_anvill_header_list
  include/anvill/IEntityLifter.h
  include/anvill/ILifterOptions.h
)

add_library(anvill STATIC
  ${public_anvill_header_list}

  src/Common/Result.h

  src/Common/LifterOptions.h
  src/Common/LifterOptions.cpp

  src/Program/Byte.h
  src/Program/Byte.cpp

  src/Program/ByteSequence.h
  src/Program/ByteSequence.cpp

  src/Program/Program.h
  src/Program/Program.cpp

  src/Decl/Decl.h
  src/Decl/TypedRegisterDecl.h

  src/Decl/FunctionDecl.h
  src/Decl/FunctionDecl.cpp

  src/Decl/GlobalVarDecl.h
  src/Decl/GlobalVarDecl.cpp

  src/Decl/ParameterDecl.h
  src/Decl/ParameterDecl.cpp

  src/Decl/ValueDecl.h
  src/Decl/ValueDecl.cpp

  src/Lifters/DeclLifter.h
  src/Lifters/DeclLifter.cpp

  src/Providers/ControlFlowProvider.h
  src/Providers/ControlFlowProvider.cpp

  src/Providers/IMemoryProvider.h
  src/Providers/IMemoryProvider.cpp

  src/Providers/MemoryProviders/NullMemoryProvider.h
  src/Providers/MemoryProviders/NullMemoryProvider.cpp

  src/Arch/Arch.h
  src/Arch/Arch.cpp
  src/Arch/AArch32_C.cpp
  src/Arch/AArch64_C.cpp
  src/Arch/AllocationState.cpp
  src/Arch/AllocationState.h
  src/Arch/SPARC32_C.cpp
  src/Arch/SPARC64_C.cpp
  src/Arch/X86_64_SysV.cpp
  src/Arch/X86_C.cpp
  src/Arch/X86_FastCall.cpp
  src/Arch/X86_StdCall.cpp
  src/Arch/X86_ThisCall.cpp
)

appendRemillVersionToTargetOutputName(anvill)

target_include_directories(anvill PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

target_link_libraries(anvill PUBLIC
  remill_settings
  remill
  anvill_version
  llvm_utils
)

set_target_properties(anvill PROPERTIES
  PUBLIC_HEADER "${public_anvill_header_list}"
)

add_subdirectory("python")

if(ANVILL_ENABLE_TESTS)
  add_subdirectory("tests")
endif()

if(ANVILL_ENABLE_INSTALL_TARGET)
  install(
    TARGETS
      anvill

    EXPORT
      anvillTargets

    LIBRARY DESTINATION
      lib

    ARCHIVE DESTINATION
      lib

    INCLUDES DESTINATION
      include

    PUBLIC_HEADER DESTINATION
      "${CMAKE_INSTALL_INCLUDEDIR}/anvill"
  )

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
endif()
