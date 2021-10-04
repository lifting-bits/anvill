#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_library(anvill_passes STATIC
  include/anvill/Transforms.h

  src/LowerRemillMemoryAccessIntrinsics.cpp
  src/LowerRemillMemoryAccessIntrinsics.h
  
  src/LowerRemillUndefinedIntrinsics.cpp
  src/LowerRemillUndefinedIntrinsics.h

  src/LowerTypeHintIntrinsics.cpp
  src/LowerTypeHintIntrinsics.h

  src/RemoveCompilerBarriers.cpp
  src/RemoveCompilerBarriers.h

  src/RemoveDelaySlotIntrinsics.cpp
  src/RemoveDelaySlotIntrinsics.h

  src/RemoveErrorIntrinsics.cpp
  src/RemoveErrorIntrinsics.h

  src/RemoveRemillFunctionReturns.cpp
  src/RemoveRemillFunctionReturns.h
  
  src/RemoveTrivialPhisAndSelects.cpp
  src/RemoveTrivialPhisAndSelects.h

  src/RemoveUnusedFPClassificationCalls.cpp
  src/RemoveUnusedFPClassificationCalls.h

  src/SinkSelectionsIntoBranchTargets.h
  src/SinkSelectionsIntoBranchTargets.cpp

  src/SplitStackFrameAtReturnAddress.h
  src/SplitStackFrameAtReturnAddress.cpp

  src/BrightenPointerOperations.h
  src/BrightenPointerOperations.cpp
  
  src/RecoverEntityUseInformation.h
  src/RecoverEntityUseInformation.cpp

  src/RecoverStackFrameInformation.cpp
  src/RecoverStackFrameInformation.h
  
  src/InstructionFolderPass.h
  src/InstructionFolderPass.cpp

  src/IndirectJumpPass.h
  src/JumpTableAnalysis.cpp
  src/JumpTableAnalysis.h
  src/SwitchLoweringPass.h
  src/SwitchLoweringPass.cpp
  src/BaseFunctionPass.h

  src/Utils.h
  src/Utils.cpp
  src/SliceManager.cpp
  src/SlicerVisitor.h
  src/SlicerVisitor.cpp
  src/SliceInterpreter.cpp

  include/anvill/ITransformationErrorManager.h
  src/TransformationErrorManager.h
  src/TransformationErrorManager.cpp
  src/TransformRemillJumpIntrinsics.cpp
  src/TransformRemillJumpIntrinsics.h

  src/ConvertXorToCmp.cpp
  src/ConvertXorToCmp.h
)

target_include_directories(anvill_passes PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

target_link_libraries(anvill_passes PUBLIC
  remill_settings
  anvill
)

target_compile_definitions(anvill_passes PRIVATE
  "LLVM_MAJOR_VERSION=${LLVM_MAJOR_VERSION}"
)

addMagicEnumLibrary(anvill_passes)

if(ANVILL_ENABLE_TESTS)
  add_subdirectory("tests")
endif()

if(ANVILL_ENABLE_INSTALL_TARGET)
  install(
    TARGETS
      anvill_passes

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
