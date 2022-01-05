/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <anvill/Providers.h>
#include <anvill/Passes/IndirectJumpPass.h>
#include <anvill/Passes/SliceManager.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>

// The goal here is to lower anvill_complete_switch to an llvm switch when we
// can recover the cases. This analysis must be sound but
// `anvill_complete_switch` maybe used for any complete set of indirect targets
// so cases may not even exist.
//
// The analysis has to prove to us that this transformation is semantically
// preserving.
//
// This pass focuses on lowering switch statements where a jump table does exist

namespace anvill {

class LowerSwitchIntrinsics
    : public IndirectJumpPass<LowerSwitchIntrinsics, llvm::PreservedAnalyses>,
      public llvm::PassInfoMixin<LowerSwitchIntrinsics> {

 private:
  const MemoryProvider &memProv;

 public:
  LowerSwitchIntrinsics(const MemoryProvider &memProv)
      : memProv(memProv) {}

  static llvm::StringRef name(void);

  llvm::PreservedAnalyses runOnIndirectJump(llvm::CallInst *indirectJump,
                                            llvm::FunctionAnalysisManager &am,
                                            llvm::PreservedAnalyses);


  static llvm::PreservedAnalyses BuildInitialResult();
};
}  // namespace anvill
