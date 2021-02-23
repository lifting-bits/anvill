#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_library(anvill STATIC
  include/anvill/Type.h

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

  include/anvill/TypeParser.h
  src/TypeParser.cpp

  include/anvill/TypePrinter.h
  src/TypePrinter.cpp

  include/anvill/Program.h
  src/Program.cpp
  
  include/anvill/RecoverMemRefs.h
  src/RecoverMemRefs.cpp

  include/anvill/Decl.h
  src/Decl.cpp

  include/anvill/Optimize.h
  src/Optimize.cpp

  include/anvill/Analyze.h
  src/Analyze.cpp

  include/anvill/Util.h
  src/Util.cpp
  
  include/anvill/Lifters/Options.h
  src/Lifters/Options.cpp
  
  include/anvill/Lifters/ValueLifter.h
  src/Lifters/ValueLifter.h
  src/Lifters/ValueLifter.cpp
  
  include/anvill/Lifters/Context.h
  src/Lifters/Context.h
  src/Lifters/Context.cpp
  
  include/anvill/Lifters/DeclLifter.h
  src/Lifters/DeclLifter.cpp
  
  include/anvill/Lifters/FunctionLifter.h
  src/Lifters/FunctionLifter.h
  src/Lifters/FunctionLifter.cpp
  
  include/anvill/Lifters/DataLifter.h
  src/Lifters/DataLifter.h
  src/Lifters/DataLifter.cpp
    
  include/anvill/Providers/MemoryProvider.h
  src/Providers/MemoryProvider.cpp
  
  include/anvill/Providers/TypeProvider.h
  src/Providers/TypeProvider.cpp
)

appendRemillVersionToTargetOutputName(anvill)

target_include_directories(anvill PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

target_link_libraries(anvill PUBLIC remill_settings remill anvill_version)

macro(target_public_headers TARGET)
  set_target_properties(${TARGET} PROPERTIES PUBLIC_HEADER "${ARGN}")
endmacro()

target_public_headers(anvill
  include/anvill/Analyze.h
  include/anvill/Decl.h
  include/anvill/Optimize.h
  include/anvill/Program.h
  include/anvill/RecoverMemRefs.h
  include/anvill/Type.h
  include/anvill/TypeParser.h
  include/anvill/TypePrinter.h
  include/anvill/Util.h
)

add_subdirectory("python")

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
