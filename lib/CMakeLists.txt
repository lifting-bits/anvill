#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

set(anvill_PUBLIC_HEADER_DIR "${PROJECT_SOURCE_DIR}/include/anvill")

# Based on: https://github.com/andrew-hardin/cmake-git-version-tracking/blob/master/better-example/CMakeLists.txt
# By Andrew Hardin
# Released under the MIT License.
# https://raw.githubusercontent.com/andrew-hardin/cmake-git-version-tracking/master/LICENSE
#
# Define the two required variables before including
# the source code for watching a git repository.
set(PRE_CONFIGURE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/Version.cpp.in")
set(POST_CONFIGURE_FILE "${CMAKE_CURRENT_BINARY_DIR}/Version.cpp")
set(GIT_WORKING_DIR "${PROJECT_SOURCE_DIR}")
include("${PROJECT_SOURCE_DIR}/cmake/git_watcher.cmake")

find_package(Protobuf REQUIRED)
protobuf_generate_cpp(
  SPEC_PROTO_SOURCES
  SPEC_PROTO_HEADERS
  "${anvill_SOURCE_DIR}/data_specifications/specification.proto"
)

# List of passes. These names should each correspond with both an `.h` and a
# `.cpp` file.
set(anvill_passes
  ConvertAddressesToEntityUses
  ConvertMasksToCasts
  ConvertSymbolicReturnAddressToConcreteReturnAddress
  ConvertXorsToCmps
  HoistUsersOfSelectsAndPhis
  JumpTableAnalysis
  BranchAnalysis
  Constraints
  LowerRemillMemoryAccessIntrinsics
  LowerRemillUndefinedIntrinsics
  RemoveCompilerBarriers
  RemoveDelaySlotIntrinsics
  RemoveErrorIntrinsics
  RemoveRemillFunctionReturns
  RemoveStackPointerCExprs
  RemoveTrivialPhisAndSelects
  RemoveUnusedFPClassificationCalls
  SinkSelectionsIntoBranchTargets
  SliceInterpreter
  SliceManager
  CodeQualityStatCollector
  RemoveUnusedBranchHints
  BranchRecovery
  SplitStackFrameAtReturnAddress
  SpreadPCMetadata
  TransformRemillJumpIntrinsics
  CombineAdjacentShifts
  ReplaceStackReferences
  RemoveCallIntrinsics
  ReplaceRemillFunctionReturnsWithAnvillFunctionReturns
)

set(anvill_arch_HEADERS
  "Arch/AllocationState.h"
  "Arch/Arch.h"
)

set(anvill_arch_SOURCES
  "Arch/AArch32_C.cpp"
  "Arch/AArch64_C.cpp"
  "Arch/AllocationState.cpp"
  "Arch/Arch.cpp"
  "Arch/SPARC32_C.cpp"
  "Arch/SPARC64_C.cpp"
  "Arch/X86_64_SysV.cpp"
  "Arch/X86_C.cpp"
  "Arch/X86_FastCall.cpp"
  "Arch/X86_StdCall.cpp"
  "Arch/X86_ThisCall.cpp"
)

set(anvill_lifters_HEADERS
  "Lifters/DataLifter.h"
  "Lifters/EntityLifter.h"
  "Lifters/FunctionLifter.h"
  "Lifters/BasicBlockLifter.h"
  "Lifters/CodeLifter.h"
  "Lifters/ValueLifter.h"
)

set(anvill_lifters_SOURCES
  "Lifters/DataLifter.cpp"
  "Lifters/EntityLifter.cpp"
  "Lifters/FunctionLifter.cpp"
  "Lifters/CodeLifter.cpp"
  "Lifters/BasicBlockLifter.cpp"
  "Lifters/Options.cpp"
  "Lifters/ValueLifter.cpp"
)

set(anvill_providers_SOURCES
  "Providers/ControlFlowProvider.cpp"
  "Providers/MemoryProvider.cpp"
  "Providers/TypeProvider.cpp"
)

set(anvill_passes_HEADERS
  "${anvill_PUBLIC_HEADER_DIR}/Passes/IndirectJumpPass.h"
)

set(anvill_passes_SOURCES
  "Passes/SlicerVisitor.cpp"
  "Passes/SlicerVisitor.h"
  "Passes/Utils.cpp"
  "Passes/Utils.h"
)

foreach(pass_name ${anvill_passes})
  list(APPEND anvill_passes_HEADERS "${anvill_PUBLIC_HEADER_DIR}/Passes/${pass_name}.h")
  list(APPEND anvill_passes_SOURCES "Passes/${pass_name}.cpp")
endforeach()

set(anvill_PUBLIC_HEADERS
  "${anvill_PUBLIC_HEADER_DIR}/ABI.h"
  "${anvill_PUBLIC_HEADER_DIR}/CrossReferenceFolder.h"
  "${anvill_PUBLIC_HEADER_DIR}/CrossReferenceResolver.h"
  "${anvill_PUBLIC_HEADER_DIR}/Declarations.h"
  "${anvill_PUBLIC_HEADER_DIR}/Lifters.h"
  "${anvill_PUBLIC_HEADER_DIR}/Optimize.h"
  "${anvill_PUBLIC_HEADER_DIR}/Providers.h"
  "${anvill_PUBLIC_HEADER_DIR}/Result.h"
  "${anvill_PUBLIC_HEADER_DIR}/Specification.h"
  "${anvill_PUBLIC_HEADER_DIR}/Transforms.h"
  "${anvill_PUBLIC_HEADER_DIR}/Type.h"
  "${anvill_PUBLIC_HEADER_DIR}/Utils.h"
  "${anvill_PUBLIC_HEADER_DIR}/Version.h"
)

set(anvill_PRIVATE_HEADERS
  ${anvill_arch_HEADERS}
  ${anvill_lifters_HEADERS}
)

set(anvill_SOURCES
  "ABI.cpp"
  "CrossReferenceFolder.cpp"
  "CrossReferenceResolver.cpp"
  "Declarations.cpp"
  "Optimize.cpp"
  "Protobuf.cpp"
  "Specification.cpp"
  "Specification.h"
  "Transforms.cpp"
  "Type.cpp"
  "Utils.cpp"
  ${POST_CONFIGURE_FILE}
)

add_library(anvill STATIC
  ${anvill_PUBLIC_HEADERS}
  ${anvill_PRIVATE_HEADERS}
  ${anvill_arch_SOURCES}
  ${anvill_lifters_SOURCES}
  ${anvill_passes_HEADERS}
  ${anvill_passes_SOURCES}
  ${anvill_providers_SOURCES}
  ${anvill_SOURCES}
  ${SPEC_PROTO_HEADERS}
  ${SPEC_PROTO_SOURCES}
)

set_target_properties(anvill
  PROPERTIES
  PUBLIC_HEADER "${anvill_PUBLIC_HEADERS}"
  LINKER_LANGUAGE CXX
)

target_include_directories(anvill PUBLIC
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
  PRIVATE "${CMAKE_CURRENT_LIST_DIR}" "${CMAKE_CURRENT_BINARY_DIR}"
)

target_link_libraries(anvill
  PUBLIC
  remill
  PRIVATE
  protobuf::libprotobuf
)

add_dependencies(anvill check_git_anvill)

if(ANVILL_ENABLE_PYTHON3_LIBS)
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../python" python)
endif()

# if(ANVILL_ENABLE_TESTS)
# add_subdirectory("tests")
# endif()
if(ANVILL_ENABLE_INSTALL)
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

  install(
    FILES
    ${anvill_passes_HEADERS}
    DESTINATION
    "${CMAKE_INSTALL_INCLUDEDIR}/anvill/Passes"
  )
endif(ANVILL_ENABLE_INSTALL)
