/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "RemoveErrorIntrinsics.h"

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

// Try to lower remill error intrinsics.
llvm::PreservedAnalyses
RemoveErrorIntrinsics::run(llvm::Function &func,
                           llvm::FunctionAnalysisManager &AM) {
  auto module = func.getParent();
  auto error = module->getFunction("__remill_error");

  if (!error) {
    return llvm::PreservedAnalyses::all();
  }

  auto calls = FindFunctionCalls(func, [=](llvm::CallBase *call) -> bool {
    return call->getCalledFunction() == error;
  });

  std::unordered_set<llvm::Instruction *> to_remove;
  std::unordered_set<llvm::BasicBlock *> affected_blocks;

  for (llvm::CallBase *call : calls) {
    if (to_remove.count(call)) {
      continue;
    }

    // Work backward through the block, up until we can remove the instruction.
    llvm::BasicBlock *const block = call->getParent();
    affected_blocks.insert(block);

    auto pred_inst = call->getPrevNode();
    for (auto inst = block->getTerminator(); inst != pred_inst;) {
      const auto next_inst = inst->getPrevNode();
      CHECK_EQ(inst->getParent(), block);
      CHECK(!to_remove.count(inst));

      if (auto itype = inst->getType(); itype && !itype->isVoidTy()) {
        inst->replaceAllUsesWith(llvm::UndefValue::get(itype));
      }

      inst->dropAllReferences();
      inst->removeFromParent();
      to_remove.insert(inst);
      inst = next_inst;
    }

    DCHECK(!block->getTerminator());
    auto unreachable_inst =
        new llvm::UnreachableInst(block->getContext(), block);

    CopyMetadataTo(call, unreachable_inst);
  }

  std::vector<llvm::PHINode *> broken_phis;
  std::vector<llvm::Value *> new_incoming_vals;
  std::vector<llvm::BasicBlock *> new_incoming_blocks;
  std::unordered_set<llvm::BasicBlock *> unreachable_blocks;

  for (auto changed = true; changed;) {
    changed = false;

    // Find PHI nodes with predecessor blocks that now no longer actually
    // flow to the PHI node.
    broken_phis.clear();
    for (llvm::BasicBlock &block : func) {
      for (llvm::Instruction &inst : block) {
        if (auto phi = llvm::dyn_cast<llvm::PHINode>(&inst)) {
          auto num_incoming_vals = phi->getNumIncomingValues();
          for (auto i = 0u; i < num_incoming_vals; ++i) {
            auto incoming_block = phi->getIncomingBlock(i);
            if (affected_blocks.count(incoming_block)) {
              broken_phis.push_back(phi);
              changed = true;
              break;
            }
          }
        } else {
          break;
        }
      }
    }

    // Rebuild the PHI nodes, or replace them with what should have been passed
    // through.
    for (llvm::PHINode *phi : broken_phis) {
      new_incoming_vals.clear();
      new_incoming_blocks.clear();

      const auto num_incoming_vals = phi->getNumIncomingValues();
      for (auto i = 0u; i < num_incoming_vals; ++i) {
        auto incoming_block = phi->getIncomingBlock(i);
        auto incoming_val = phi->getIncomingValue(i);
        if (affected_blocks.count(incoming_block) ||
            to_remove.count(llvm::dyn_cast<llvm::Instruction>(incoming_val))) {
          continue;
        } else {
          new_incoming_vals.push_back(incoming_val);
          new_incoming_blocks.push_back(incoming_block);
        }
      }

      llvm::Value *phi_replacement = nullptr;

      // This block is technically unreachable.
      if (new_incoming_vals.empty()) {
        llvm::BasicBlock *phi_block = phi->getParent();
        unreachable_blocks.insert(phi_block);
        affected_blocks.insert(phi_block);
        phi_replacement = llvm::UndefValue::get(phi->getType());

      // Only one incoming value; forward it along.
      } else if (new_incoming_vals.size() == 1u) {
        phi_replacement = new_incoming_vals[0];

      // Create a new PHI node.
      } else {
        auto new_phi = llvm::PHINode::Create(
            phi->getType(), static_cast<unsigned>(new_incoming_vals.size()),
            llvm::Twine::createNull(), phi);
        CopyMetadataTo(phi, new_phi);

        auto i = 0u;
        for (auto val : new_incoming_vals) {
          new_phi->addIncoming(val, new_incoming_blocks[i++]);
        }

        phi_replacement = new_phi;
      }

      phi->replaceAllUsesWith(phi_replacement);
      phi->dropAllReferences();
      phi->removeFromParent();
      to_remove.insert(phi);
    }
  }

  // Get rid of any instructions that we removed from the basic blocks.
  for (llvm::Instruction *inst : to_remove) {
    inst->deleteValue();
  }

  return ConvertBoolToPreserved(!to_remove.empty());
}
// Removes calls to `__remill_error`.
void AddRemoveErrorIntrinsics(llvm::FunctionPassManager &fpm) {
  fpm.addPass(RemoveErrorIntrinsics());
}
}  // namespace anvill
