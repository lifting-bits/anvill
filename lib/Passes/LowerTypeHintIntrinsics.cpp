/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
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
