/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "LowerRemillUndefinedIntrinsics.h"

#include <anvill/ABI.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include <vector>

#include "Utils.h"

namespace anvill {


llvm::PreservedAnalyses
LowerRemillUndefinedIntrinsics::run(llvm::Function &func,
                                    llvm::FunctionAnalysisManager &AM) {
  std::vector<llvm::CallInst *> calls;

  for (auto &inst : llvm::instructions(func)) {
    if (auto call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
      if (auto callee = call->getCalledFunction();
          callee && callee->getName().startswith("__remill_undefined_")) {
        calls.push_back(call);
      }
    }
  }

  auto changed = false;
  for (auto call : calls) {
    auto *undef_val = llvm::UndefValue::get(call->getType());
    CopyMetadataTo(call, undef_val);
    call->replaceAllUsesWith(undef_val);
    call->eraseFromParent();
    changed = true;
  }

  return ConvertBoolToPreserved(changed);
}

// Some machine code instructions explicitly introduce undefined values /
// behavior. Often, this is a result of the CPUs of different steppings of
// an ISA producing different results for specific registers. For example,
// some instructions leave the value of specific arithmetic flags instructions
// in an undefined state.
//
// Remill models these situations using opaque function calls, i.e. an
// undefined value is produced via a call to something like
// `__remill_undefined_8`, which represents an 8-bit undefined value. We want
// to lower these to `undef` values in LLVM; however, we don't want to do this
// too early, otherwise the "undefinedness" can spread and possibly get out
// of control.
//
// This pass exists to do the lowering to `undef` values, and should be run
// as late as possible.
void AddLowerRemillUndefinedIntrinsics(llvm::FunctionPassManager &fpm) {
  fpm.addPass(LowerRemillUndefinedIntrinsics());
}

}  // namespace anvill
