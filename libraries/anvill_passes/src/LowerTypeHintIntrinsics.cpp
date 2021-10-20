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

#include "LowerTypeHintIntrinsics.h"

#include <anvill/ABI.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include <vector>

#include "Utils.h"

namespace anvill {


llvm::PreservedAnalyses
LowerTypeHintIntrinsics::run(llvm::Function &func,
                             llvm::FunctionAnalysisManager &AM) {
  std::vector<llvm::CallInst *> calls;

  for (auto &inst : llvm::instructions(func)) {
    if (auto call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
      if (auto callee = call->getCalledFunction();
          callee && callee->getName().startswith(kTypeHintFunctionPrefix)) {
        calls.push_back(call);
      }
    }
  }

  auto changed = false;
  for (auto call : calls) {
    auto val = call->getArgOperand(0)->stripPointerCasts();
    llvm::IRBuilder<> ir(call);
    auto *cast_val = ir.CreateBitOrPointerCast(val, call->getType());
    CopyMetadataTo(call, cast_val);
    call->replaceAllUsesWith(cast_val);
    changed = true;
  }

  for (auto call : calls) {
    if (call->use_empty()) {
      call->eraseFromParent();
      changed = true;
    }
  }

  return ConvertBoolToPreserved(changed);
}

void AddLowerTypeHintIntrinsics(llvm::FunctionPassManager &fpm) {
  fpm.addPass(LowerTypeHintIntrinsics());
}

}  // namespace anvill
