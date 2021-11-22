/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "RemoveDelaySlotIntrinsics.h"

#include <anvill/Transforms.h>
#include <glog/logging.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>

#include "Utils.h"

namespace anvill {


// Try to lower remill memory access intrinsics.
llvm::PreservedAnalyses
RemoveDelaySlotIntrinsics::run(llvm::Function &func,
                               llvm::FunctionAnalysisManager &AM) {
  auto module = func.getParent();
  auto begin = module->getFunction("__remill_delay_slot_begin");
  auto end = module->getFunction("__remill_delay_slot_end");

  if (!begin && !end) {
    return llvm::PreservedAnalyses::all();
  }

  auto calls = FindFunctionCalls(func, [=](llvm::CallBase *call) -> bool {
    const auto func = call->getCalledFunction();
    return func == begin || func == end;
  });

  for (llvm::CallBase *call : calls) {
    auto mem_ptr = call->getArgOperand(0);
    CopyMetadataTo(call, mem_ptr);
    call->replaceAllUsesWith(mem_ptr);
    call->eraseFromParent();
  }

  return ConvertBoolToPreserved(!calls.empty());
}

// Removes calls to `__remill_delay_slot_begin` and `__remill_delay_slot_end`.
void AddRemoveDelaySlotIntrinsics(llvm::FunctionPassManager &fpm) {
  fpm.addPass(RemoveDelaySlotIntrinsics());
}
}  // namespace anvill
