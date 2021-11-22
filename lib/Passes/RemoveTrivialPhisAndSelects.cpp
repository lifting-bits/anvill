/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "RemoveTrivialPhisAndSelects.h"

#include <anvill/Transforms.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>

#include <unordered_set>
#include <utility>
#include <vector>

#include "RemoveTrivialPhisAndSelects.h"
#include "Utils.h"

namespace anvill {

llvm::PreservedAnalyses
RemoveTrivialPhisAndSelects::run(llvm::Function &func,
                                 llvm::FunctionAnalysisManager &AM) {

  std::unordered_set<llvm::Instruction *> remove;
  std::vector<llvm::Instruction *> work_list;
  std::vector<llvm::Instruction *> next_work_list;
  std::vector<std::pair<llvm::Use *, llvm::Value *>> replacements;

  auto changed = false;

  {
    for (auto &inst : llvm::instructions(func)) {
      next_work_list.push_back(&inst);
    }
  }

  while (!next_work_list.empty()) {
    next_work_list.swap(work_list);
    next_work_list.clear();

    for (auto inst : work_list) {

      // Check if `inst` is a `phi [BB0, VAL], ..., [BBn, VAL]`, and schedule a
      // replacement of the `phi` with `VAL`.
      if (auto phi = llvm::dyn_cast<llvm::PHINode>(inst)) {
        const auto base_val = phi->getIncomingValue(0);
        for (auto &use : phi->incoming_values()) {
          const auto val = use.get();
          if (val != base_val) {
            goto next;
          }
        }

        for (auto &use : phi->uses()) {
          replacements.emplace_back(&use, base_val);
        }
        remove.insert(phi);

      next:
        continue;

        // Check if `inst` is a `select cond, VAL, VAL`, and schedule a
        // replacement of the `select` with `VAL`.
      } else if (auto sel = llvm::dyn_cast<llvm::SelectInst>(inst)) {
        const auto base_val = sel->getTrueValue();
        if (base_val == sel->getFalseValue()) {
          for (auto &use : sel->uses()) {
            replacements.emplace_back(&use, base_val);
          }
          remove.insert(sel);
        }
      }
    }

    // If one PHI/Select leads to another, then this will possibly help
    // us handle those situations.
    for (auto [use, new_val] : replacements) {
      if (auto user_inst = llvm::dyn_cast<llvm::Instruction>(use->getUser())) {
        next_work_list.push_back(user_inst);
      }
      use->set(new_val);
      changed = true;
    }

    replacements.clear();
  }

  // Remove the no longer needed instructions.
  for (auto inst : remove) {
    if (inst->use_empty()) {
      inst->eraseFromParent();
      changed = true;
    }
  }

  return ConvertBoolToPreserved(changed);
}

// Removes trivial PHI and select nodes. These are PHI and select nodes whose
// incoming values or true/false values match. This can happen as a result of
// the instruction folding pass that hoists and folds values up through selects
// and PHI nodes, followed by the select sinking pass, which pushes values down.
void AddRemoveTrivialPhisAndSelects(llvm::FunctionPassManager &fpm) {
  fpm.addPass(RemoveTrivialPhisAndSelects());
}
}  // namespace anvill
