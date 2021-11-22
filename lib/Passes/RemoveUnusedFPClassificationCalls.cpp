/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "RemoveUnusedFPClassificationCalls.h"

#include <anvill/Transforms.h>
#include <glog/logging.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>

#include "Utils.h"

namespace anvill {
// Try to remove unused floating point classification function calls.
llvm::PreservedAnalyses RemoveUnusedFPClassificationCalls::run(
    llvm::Function &func, llvm::FunctionAnalysisManager &analysisManager) {
  auto calls = FindFunctionCalls(func, [](llvm::CallBase *call) -> bool {
    const auto func = call->getCalledFunction();
    if (!func) {
      return false;
    }

    const auto name = func->getName();
    return name == "fpclassify" || name == "__fpclassifyd" ||
           name == "__fpclassifyf" || name == "__fpclassifyld";
  });

  auto ret = false;
  for (llvm::CallBase *call : calls) {
    if (call->use_empty()) {
      call->eraseFromParent();
      ret = true;
    }
  }

  return ConvertBoolToPreserved(ret);
}
// Remove unused calls to floating point classification functions. Calls to
// these functions are present in a bunch of FPU-related instruction semantics
// functions. It's frequently the case that instructions don't actually care
// about the FPU state, though. In these cases, we won't observe the return
// values of these classification functions being used. However, LLVM can't
// eliminate the calls to these functions on its own because they are not
// "pure" functions.
//
// NOTE(pag): This pass must be applied before any kind of renaming of lifted
//            functions is performed, so that we don't accidentally remove
//            calls to classification functions present in the target binary.
void AddRemoveUnusedFPClassificationCalls(llvm::FunctionPassManager &fpm) {
  fpm.addPass(RemoveUnusedFPClassificationCalls());
}


}  // namespace anvill
