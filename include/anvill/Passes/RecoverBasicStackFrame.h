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

class StackFrameRecoveryOptions;

// This function pass recovers stack information by analyzing the usage
// of the `__anvill_sp` symbol
class RecoverBasicStackFrame final
    : public llvm::PassInfoMixin<RecoverBasicStackFrame> {

  // Lifting options
  const StackFrameRecoveryOptions &options;

 public:

  // Function pass entry point
  llvm::PreservedAnalyses run(llvm::Function &func,
                              llvm::FunctionAnalysisManager &fam);

  // Returns the pass name
  static llvm::StringRef name(void);

  inline explicit RecoverBasicStackFrame(
      const StackFrameRecoveryOptions &options_)
      : options(options_) {}
};

}  // namespace anvill
