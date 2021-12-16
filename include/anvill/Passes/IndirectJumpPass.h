/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <anvill/ABI.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>

namespace anvill {
namespace {

// NOTE(ian): The jump table analysis could also be targeted towards
//            incomplete switch intrinsics.
//
// It is always safe to run this analysis because the bounds on the index are
// conservative. That being said if the intrinsic is truly incomplete when we
// attempt to lower the switch there will be missing labels in the PC binding
// mapping, therefore it is unlikely the switch lowering pass should be run
// against the incomplete switches. Perhaps the best solution here is to run
// the jump table analysis on its own against incomplete switches and allow it
// to call back into the lifter for more code.
static bool isTargetInstrinsic(const llvm::CallInst *callinsn) {
  if (const auto *callee = callinsn->getCalledFunction()) {
    return callee->getName().equals(kAnvillSwitchCompleteFunc);
  }

  return false;
}

static inline std::vector<llvm::CallInst *>
getTargetCalls(llvm::Function &fromFunction) {
  std::vector<llvm::CallInst *> calls;
  for (auto &insn : llvm::instructions(fromFunction)) {
    llvm::Instruction *new_insn = &insn;
    if (llvm::CallInst *call_insn = llvm::dyn_cast<llvm::CallInst>(new_insn)) {
      if (isTargetInstrinsic(call_insn)) {
        calls.push_back(call_insn);
      }
    }
  }
  return calls;
}
}  // namespace

// NOTE(ian): Unfortunately pretty sure CRTP is the only way to do this without
//            running into issues with pass IDs
template <typename UserFunctionPass, typename Result>
class IndirectJumpPass {
 public:
  IndirectJumpPass(void) {}

  Result run(llvm::Function &F, llvm::FunctionAnalysisManager &am);
};


template <typename UserFunctionPass, typename Result>
Result IndirectJumpPass<UserFunctionPass, Result>::run(
    llvm::Function &F, llvm::FunctionAnalysisManager &am) {
  auto &function_pass = *static_cast<UserFunctionPass *>(this);
  Result total = UserFunctionPass::BuildInitialResult();
  for (auto targetCall : getTargetCalls(F)) {
    total = function_pass.runOnIndirectJump(targetCall, am, std::move(total));
  }

  return total;
}

}  // namespace anvill