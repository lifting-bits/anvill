/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Passes/ConvertIntegerToPointerOperations.h>

#include <anvill/Transforms.h>

#include "Utils.h"

namespace anvill {

llvm::StringRef ConvertIntegerToPointerOperations::name(void) {
  return "PointerLifter";
}

llvm::PreservedAnalyses ConvertIntegerToPointerOperations::run(
    llvm::Function &func, llvm::FunctionAnalysisManager &fam) {
  return llvm::PreservedAnalyses::all();
}

void AddConvertIntegerToPointerOperations(llvm::FunctionPassManager &fpm) {
  fpm.addPass(ConvertIntegerToPointerOperations());
}
}  // namespace anvill
