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

// Look for uses of the `(ptrtoint __remill_ra)` constant expression
// representing uses of the return address, and translate them to concrete uses
// of the return address.
class ConvertSymbolicReturnAddressToConcreteReturnAddress final :
    public llvm::PassInfoMixin<ConvertSymbolicReturnAddressToConcreteReturnAddress> {
 public:
  llvm::PreservedAnalyses run(llvm::Function &func,
                              llvm::FunctionAnalysisManager &fam);

  static llvm::StringRef name(void);
};

}  // namespace anvill
