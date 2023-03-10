/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <anvill/Declarations.h>
#include <anvill/Type.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/PassManager.h>

#include <optional>
#include <unordered_map>
#include <vector>

#include "BasicBlockPass.h"

namespace anvill {

class ConvertPointerArithmeticToGEP final
    : public BasicBlockPass<ConvertPointerArithmeticToGEP> {
 private:
  struct Impl;
  std::unique_ptr<Impl> impl;

 public:
  using StructMap = std::unordered_map<StructType *, llvm::StructType *>;
  using TypeMap = std::unordered_map<llvm::MDNode *, TypeSpec>;
  using MDMap = std::unordered_map<void *, llvm::MDNode *>;

  llvm::PreservedAnalyses
  runOnBasicBlockFunction(llvm::Function &F, llvm::FunctionAnalysisManager &AM,
                          const anvill::BasicBlockContext &,
                          const FunctionDecl &);

  // Returns the pass name
  static llvm::StringRef name(void);

  ConvertPointerArithmeticToGEP(const BasicBlockContexts &contexts,
                                TypeMap &types, StructMap &structs, MDMap &md);
  ConvertPointerArithmeticToGEP(const ConvertPointerArithmeticToGEP &);
  ~ConvertPointerArithmeticToGEP();
};

}  // namespace anvill
