/*
 * Copyright (c) 2021 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <anvill/ABI.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>

namespace anvill {

template <typename UserFunctionPass, typename Result>
class IntrinsicPass {

 private:
  static std::vector<llvm::CallInst *>
  getTargetCalls(llvm::Function &fromFunction) {
    std::vector<llvm::CallInst *> calls;
    for (auto &insn : llvm::instructions(fromFunction)) {
      llvm::Instruction *new_insn = &insn;
      if (llvm::CallInst *call_insn =
              llvm::dyn_cast<llvm::CallInst>(new_insn)) {
        if (UserFunctionPass::isTargetInstrinsic(call_insn)) {
          calls.push_back(call_insn);
        }
      }
    }
    return calls;
  }

 public:
  IntrinsicPass(void) {}

  Result run(llvm::Function &F, llvm::FunctionAnalysisManager &am);
};


template <typename UserFunctionPass, typename Result>
Result IntrinsicPass<UserFunctionPass, Result>::run(
    llvm::Function &F, llvm::FunctionAnalysisManager &am) {
  auto &function_pass = *static_cast<UserFunctionPass *>(this);
  Result total = function_pass.INIT_RES;
  for (auto targetCall : getTargetCalls(F)) {
    total = function_pass.runOnIntrinsic(targetCall, am, std::move(total));
  }

  return total;
}
}  // namespace anvill