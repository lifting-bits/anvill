#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_library(anvill STATIC
  include/anvill/Type.h
  include/anvill/Result.h

  src/Arch/AArch32_C.cpp
  src/Arch/AArch64_C.cpp
  src/Arch/SPARC32_C.cpp
  src/Arch/SPARC64_C.cpp
  src/Arch/X86_C.cpp
  src/Arch/X86_FastCall.cpp
  src/Arch/X86_StdCall.cpp
  src/Arch/X86_ThisCall.cpp
  src/Arch/X86_64_SysV.cpp

  src/Arch/AllocationState.h
  src/Arch/AllocationState.cpp

  src/Arch/Arch.h
  src/Arch/Arch.cpp

  include/anvill/ITypeSpecification.h
  src/TypeSpecification.h
  src/TypeSpecification.cpp

  include/anvill/Program.h
  src/Program.cpp

  include/anvill/Decl.h
  src/Decl.cpp

  include/anvill/Optimize.h
  src/Optimize.cpp

  include/anvill/Util.h
  src/Util.cpp
  
  include/anvill/Lifters/Options.h
  src/Lifters/Options.cpp
  
  include/anvill/Lifters/ValueLifter.h
  src/Lifters/ValueLifter.h
  src/Lifters/ValueLifter.cpp
  
  include/anvill/Lifters/EntityLifter.h
  src/Lifters/EntityLifter.h
  src/Lifters/EntityLifter.cpp
  
  include/anvill/Lifters/DeclLifter.h
  src/Lifters/DeclLifter.cpp
  
  src/Lifters/FunctionLifter.h
  src/Lifters/FunctionLifter.cpp
  
  src/Lifters/DataLifter.h
  src/Lifters/DataLifter.cpp
  
  include/anvill/ABI.h
  src/ABI.cpp

  include/anvill/Analysis/Utils.h
  src/Analysis/Utils.cpp

  include/anvill/Analysis/CrossReferenceResolver.h  
  src/Analysis/CrossReferenceResolver.cpp

  include/anvill/Providers/MemoryProvider.h
  src/Providers/MemoryProvider.cpp
  
  include/anvill/Providers/TypeProvider.h
  src/Providers/TypeProvider.cpp

  include/anvill/Providers/IControlFlowProvider.h
  src/Providers/ControlFlowProvider.h
  src/Providers/ControlFlowProvider.cpp
)

appendRemillVersionToTargetOutputName(anvill)

target_include_directories(anvill PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

target_link_libraries(anvill PUBLIC
  remill_settings
  remill
  anvill_version
  anvill_passes
)

macro(target_public_headers TARGET)
  set_target_properties(${TARGET} PROPERTIES PUBLIC_HEADER "${ARGN}")
endmacro()

target_public_headers(anvill
  include/anvill/Decl.h
  include/anvill/Optimize.h
  include/anvill/Program.h
  include/anvill/Result.h
  include/anvill/Type.h
  include/anvill/ITypeSpecification.h
  include/anvill/Util.h
)

if (ANVILL_BUILD_PYTHON3_LIBS)
  add_subdirectory("python")
endif()

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
