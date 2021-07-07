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

#include <anvill/Transforms.h>
#include <glog/logging.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>

#include <unordered_set>

#include "Utils.h"

namespace anvill {
namespace {

class RemoveErrorIntrinsics final : public llvm::FunctionPass {
 public:
  RemoveErrorIntrinsics(void) : llvm::FunctionPass(ID) {}

  bool runOnFunction(llvm::Function &func) final;

 private:
  static char ID;
};

char RemoveErrorIntrinsics::ID = '\0';

// Try to lower remill error intrinsics.
bool RemoveErrorIntrinsics::runOnFunction(llvm::Function &func) {
  auto module = func.getParent();
  auto error = module->getFunction("__remill_error");

  if (!error) {
    return false;
  }

  auto calls = FindFunctionCalls(func, [=](llvm::CallBase *call) -> bool {
    const auto func = call->getCalledFunction();
    return func == error;
  });

  std::unordered_set<llvm::Instruction *> removed;

  for (llvm::CallBase *call : calls) {
    if (removed.count(call)) {
      continue;
    }

    // Work backward through the block, up until we can remove the instruction.
    auto block = call->getParent();
    auto pred_inst = call->getPrevNode();
    for (auto inst = block->getTerminator(); inst != pred_inst; ) {
      const auto next_inst = inst->getPrevNode();
      CHECK_EQ(inst->getParent(), block);

      if (auto itype = inst->getType(); itype && !itype->isVoidTy()) {
        inst->replaceAllUsesWith(llvm::UndefValue::get(itype));
        inst->dropAllReferences();
        inst->eraseFromParent();
        removed.insert(inst);
      }

      inst = next_inst;
    }

    DCHECK(!block->getTerminator());
    (void) new llvm::UnreachableInst(block->getContext(), block);
  }

  return !removed.empty();
}

}  // namespace

// Removes calls to `__remill_error`.
llvm::FunctionPass *CreateRemoveErrorIntrinsics(void) {
  return new RemoveErrorIntrinsics;
}

}  // namespace anvill
