/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Passes/RemoveCompilerBarriers.h>

#include <anvill/Transforms.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>

#include "Utils.h"

namespace anvill {

llvm::StringRef RemoveCompilerBarriers::name(void) {
  return "RemoveCompilerBarriers";
}

// Try to lower remill memory access intrinsics.
llvm::PreservedAnalyses
RemoveCompilerBarriers::run(llvm::Function &func,
                            llvm::FunctionAnalysisManager &AM) {
  std::vector<llvm::CallBase *> to_remove;

  for (llvm::BasicBlock &block : func) {
    auto prev_is_compiler_barrier = false;
    llvm::CallBase *prev_barrier = nullptr;
    for (auto &inst : block) {
      if (auto call = llvm::dyn_cast<llvm::CallBase>(&inst)) {
        const auto called_val = call->getCalledOperand();
        const auto inline_asm = llvm::dyn_cast<llvm::InlineAsm>(called_val);
        if (inline_asm) {
          if (inline_asm->hasSideEffects() && call->getType()->isVoidTy() &&
              inline_asm->getAsmString().empty()) {

            if (prev_is_compiler_barrier) {
              to_remove.push_back(call);
            } else {
              prev_barrier = call;
            }
            prev_is_compiler_barrier = true;

          } else {
            prev_is_compiler_barrier = false;
            prev_barrier = nullptr;
          }

        } else if (auto target_func = call->getCalledFunction()) {
          if (target_func->hasExternalLinkage()) {
            if (prev_is_compiler_barrier && prev_barrier) {
              to_remove.push_back(prev_barrier);
            }
            prev_is_compiler_barrier = true;
          } else {
            prev_is_compiler_barrier = false;
          }

          prev_barrier = nullptr;

        } else {
          prev_is_compiler_barrier = false;
          prev_barrier = nullptr;
        }
      } else {
        prev_is_compiler_barrier = false;
        prev_barrier = nullptr;
      }
    }
  }

  auto removed = false;
  for (auto call_inst : to_remove) {
    if (call_inst->use_empty()) {
      call_inst->eraseFromParent();
      removed = true;
    }
  }

  return ConvertBoolToPreserved(removed);
}

// Remill semantics sometimes contain compiler barriers (empty inline assembly
// statements), especially related to floating point code (i.e. preventing
// re-ordering of floating point operations so that we can capture the flags).
// This pass eliminates those empty inline assembly statements.
void AddRemoveCompilerBarriers(llvm::FunctionPassManager &fpm) {
  fpm.addPass(RemoveCompilerBarriers());
}
}  // namespace anvill
