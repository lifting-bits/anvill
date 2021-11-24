/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <llvm/IR/PassManager.h>
#include <vector>

namespace llvm {
class BasicBlock;
class Function;
class Instruction;
class Value;
}  // namespace llvm
namespace anvill {

// This function pass will attempt to hoist uses of `select` and `phi` through
// the `select` and `phi`s themselves. For example, if there is:
//
//      %b = select %cond, %x, %y
//      %a = add %b, %c
//
// Then this pass produces the following:
//
//      %x_b = add %x, %c
//      %y_b = add %y, %c
//      %a = select %cond, %x_b, %y_b
//
// The idea is that we want to be able to make things like address calculations
// unconditional.
class HoistUsersOfSelectsAndPhis final
    : public llvm::PassInfoMixin<HoistUsersOfSelectsAndPhis> {
 public:
  using InstructionList = std::vector<llvm::Instruction *>;

  llvm::PreservedAnalyses run(llvm::Function &function,
                              llvm::FunctionAnalysisManager &fam);

  static llvm::StringRef name(void);

  class PassFunctionState;
};

}  // namespace anvill
