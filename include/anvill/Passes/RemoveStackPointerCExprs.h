/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>

namespace anvill {

// This pass unrolls constant expressions that involve the stack pointer
// into instructions so that RecoverStackInformation can replace the stack
// pointer with its stack representation. The pass strips away portions of the
// constant expression that cant be resolved to a stack reference so that
// hopefully they will be resolved later.
//
// define i1 @slice() local_unnamed_addr #2 {
//     %1 = call zeroext i1 (i1, ...) @__remill_flag_computation_sign(
//          i1 zeroext icmp slt
//              (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -12), i32 0),
//              i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -12)) #5
//     ret i1 %1
// }
//
// Becomes:
// define i1 @slice() local_unnamed_addr {
//   %1 = icmp slt i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -12), 0
//   %2 = call zeroext i1 (i1, ...) @__remill_flag_computation_sign(i1 zeroext %1, i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -12))
//   ret i1 %2
// }
// }

class StackFrameRecoveryOptions;

class RemoveStackPointerCExprs final
    : public llvm::PassInfoMixin<RemoveStackPointerCExprs> {
 private:
  const StackFrameRecoveryOptions &options;
 public:

  inline explicit RemoveStackPointerCExprs(
      const StackFrameRecoveryOptions &options_)
      : options(options_) {}

  static llvm::StringRef name(void);
  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);
};

}  // namespace anvill
