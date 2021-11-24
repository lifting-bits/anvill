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
  "Lifters/ValueLifter.h"
)

set(anvill_lifters_SOURCES
  "Lifters/DataLifter.cpp"
  "Lifters/EntityLifter.cpp"
  "Lifters/FunctionLifter.cpp"
  "Lifters/Options.cpp"
  "Lifters/ValueLifter.cpp"
)

set(anvill_providers_SOURCES
  "Providers/ControlFlowProvider.cpp"
  "Providers/MemoryProvider.cpp"
  "Providers/TypeProvider.cpp"
)

set(anvill_passes_HEADERS
  "${anvill_PUBLIC_HEADER_DIR}/Passes/BaseFunctionPass.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/BrightenPointerOperations.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/ConvertMasksToCasts.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/ConvertXorToCmp.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/EquivalencePass.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/IndirectJumpPass.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/InstructionFolderPass.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/JumpTableAnalysis.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/LowerRemillMemoryAccessIntrinsics.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/LowerRemillUndefinedIntrinsics.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/LowerTypeHintIntrinsics.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/RecoverEntityUseInformation.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/RecoverStackFrameInformation.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/RemoveCompilerBarriers.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/RemoveDelaySlotIntrinsics.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/RemoveErrorIntrinsics.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/RemoveRemillFunctionReturns.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/RemoveTrivialPhisAndSelects.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/SinkSelectionsIntoBranchTargets.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/SliceInterpreter.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/SliceManager.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/SlicerVisitor.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/SplitStackFrameAtReturnAddress.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/SwitchLoweringPass.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/TransformRemillJumpIntrinsics.h"
  "${anvill_PUBLIC_HEADER_DIR}/Passes/Utils.h"
)

set(anvill_PUBLIC_HEADERS
  "${anvill_PUBLIC_HEADER_DIR}/ABI.h"
  "${anvill_PUBLIC_HEADER_DIR}/ControlFlowProvider.h"
  "${anvill_PUBLIC_HEADER_DIR}/CrossReferenceFolder.h"
  "${anvill_PUBLIC_HEADER_DIR}/CrossReferenceResolver.h"
  "${anvill_PUBLIC_HEADER_DIR}/Lifter.h"
  "${anvill_PUBLIC_HEADER_DIR}/JSON.h"
  "${anvill_PUBLIC_HEADER_DIR}/MemoryProvider.h"
  "${anvill_PUBLIC_HEADER_DIR}/Optimize.h"
  "${anvill_PUBLIC_HEADER_DIR}/Result.h"
  "${anvill_PUBLIC_HEADER_DIR}/Specification.h"
  "${anvill_PUBLIC_HEADER_DIR}/Transforms.h"
  "${anvill_PUBLIC_HEADER_DIR}/Type.h"
  "${anvill_PUBLIC_HEADER_DIR}/TypeProvider.h"
  "${anvill_PUBLIC_HEADER_DIR}/Util.h"
  "${anvill_PUBLIC_HEADER_DIR}/Version.h"
  ${anvill_passes_HEADERS}
)

set(anvill_PRIVATE_HEADERS
  ${anvill_arch_HEADERS}
  ${anvill_lifters_HEADERS}
)

set(anvill_SOURCES
  "ABI.cpp"
  "CrossReferenceFolder.cpp"
  "CrossReferenceResolver.cpp"
  "JSON.cpp"
  "Specification.cpp"
  "Optimize.cpp"
  "Transforms.cpp"
  "Type.cpp"
  "Util.cpp"
  ${POST_CONFIGURE_FILE}
)

add_library(anvill STATIC
  ${anvill_PUBLIC_HEADERS}
  ${anvill_PRIVATE_HEADERS}
  ${anvill_arch_SOURCES}
  ${anvill_lifters_SOURCES}
  ${anvill_providers_SOURCES}
  ${anvill_SOURCES}
)

set_target_properties(anvill
  PROPERTIES
    PUBLIC_HEADER "${anvill_PUBLIC_HEADERS}"
    LINKER_LANGUAGE CXX
)

target_include_directories(anvill PUBLIC
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
  PRIVATE "${CMAKE_CURRENT_LIST_DIR}"
)

target_link_libraries(anvill
  PUBLIC
    remill_settings
    remill
)

add_dependencies(anvill check_git_anvill)

#if (ANVILL_ENABLE_PYTHON3_LIBS)
#  add_subdirectory("python")
#endif()

#if(ANVILL_ENABLE_TESTS)
#  add_subdirectory("tests")
#endif()

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
endif()
