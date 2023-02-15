/*
 * Copyright (c) 2023-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <anvill/Specification.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>

namespace anvill {

class InlineBasicBlocks final : public llvm::PassInfoMixin<InlineBasicBlocks> {
 public:
  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static llvm::StringRef name(void);
};
}  // namespace anvill