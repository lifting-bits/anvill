/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <llvm/IR/PassManager.h>

namespace anvill {

class RemoveTrivialPhisAndSelects final
    : public llvm::PassInfoMixin<RemoveTrivialPhisAndSelects> {
 public:
  static llvm::StringRef name(void);

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);
};

}  // namespace anvill
