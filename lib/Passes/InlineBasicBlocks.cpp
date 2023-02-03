/*
 * Copyright (c) 2023-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Passes/InlineBasicBlocks.h>
#include <anvill/Specification.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Transforms/Utils/Cloning.h>

#include "anvill/Utils.h"

namespace anvill {
llvm::StringRef InlineBasicBlocks::name() {
  return "InlineBasicBlocks";
}

llvm::PreservedAnalyses
InlineBasicBlocks::run(llvm::Function &function,
                       llvm::FunctionAnalysisManager &analysisManager) {
  auto ptr = anvill::GetBasicBlockAddr(&function);
  if (ptr.has_value()) {
    return llvm::PreservedAnalyses::all();
  }

  bool did_anything = false;
  bool inlined_something = false;
  do {
    inlined_something = false;
    for (auto &inst : llvm::instructions(function)) {
      if (auto call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
        auto callee = call->getCalledFunction();
        auto callee_addr = anvill::GetBasicBlockAddr(callee);
        if (!callee_addr.has_value()) {
          continue;
        }

        llvm::InlineFunctionInfo ifi;
        auto res = llvm::InlineFunction(*call, ifi);
        if (!res.isSuccess()) {
          LOG(ERROR) << "Could not inline call to block at address "
                     << *callee_addr;
        }
        did_anything = true;
        inlined_something = true;
        break;
      }
    }
  } while (inlined_something);
  return did_anything ? llvm::PreservedAnalyses::all()
                      : llvm::PreservedAnalyses::none();
}
}  // namespace anvill