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

class RemoveUnusedFPClassificationCalls final
    : public llvm::PassInfoMixin<RemoveUnusedFPClassificationCalls> {
 public:
  static llvm::StringRef name(void);

  llvm::PreservedAnalyses run(llvm::Function &function,
                              llvm::FunctionAnalysisManager &analysisManager);
};
}  // namespace anvill
