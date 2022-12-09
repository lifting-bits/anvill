/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Passes/ConvertPointerArithmeticToGEP.h>
#include <anvill/Type.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Type.h>

namespace anvill {
struct ConvertPointerArithmeticToGEP::Impl {};

ConvertPointerArithmeticToGEP::ConvertPointerArithmeticToGEP()
    : impl(std::make_unique<Impl>()) {}

llvm::StringRef ConvertPointerArithmeticToGEP::name() {
  return "ConvertPointerArithmeticToGEP";
}

llvm::PreservedAnalyses
ConvertPointerArithmeticToGEP::run(llvm::Function &function,
                                   llvm::FunctionAnalysisManager &fam) {

  return llvm::PreservedAnalyses::none();
}
}  // namespace anvill