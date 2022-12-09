/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/PassManager.h>

#include <optional>
#include <unordered_map>
#include <vector>

namespace anvill {

class ConvertPointerArithmeticToGEP final
    : public llvm::PassInfoMixin<ConvertPointerArithmeticToGEP> {
 private:
  struct Impl;
  std::unique_ptr<Impl> impl;

 public:
  // Function pass entry point
  llvm::PreservedAnalyses run(llvm::Function &function,
                              llvm::FunctionAnalysisManager &fam);

  // Returns the pass name
  static llvm::StringRef name(void);

  ConvertPointerArithmeticToGEP();
};

}  // namespace anvill
