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

#include <anvill/Transforms.h>

#include <llvm/IR/Dominators.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>

#include <utility>
#include <vector>

namespace anvill {
namespace {

class SinkSelectionsIntoBranchTargets final : public llvm::FunctionPass {
 public:

  SinkSelectionsIntoBranchTargets(void)
      : llvm::FunctionPass(ID) {}

  bool runOnFunction(llvm::Function &func) final;

 private:
  static char ID;
};

char SinkSelectionsIntoBranchTargets::ID = '\0';

// Try to sink selected values.
bool SinkSelectionsIntoBranchTargets::runOnFunction(llvm::Function &func) {

  std::vector<std::pair<llvm::SelectInst *, llvm::BranchInst *>>
      select_branches;

  // Go identify all `select` instructions in `func`, where the `select`
  // shares the same condition as a conditional branch.
  for (auto &inst : llvm::instructions(func)) {
    if (auto select = llvm::dyn_cast<llvm::SelectInst>(&inst)) {
      const auto sel_cond = select->getCondition();
      for (auto &use : sel_cond->uses()) {
        if (const auto br = llvm::dyn_cast<llvm::BranchInst>(use.getUser());
            br && br->isConditional() && br->getCondition() == sel_cond) {
          select_branches.emplace_back(select, br);
        }
      }
    }
  }

  if (select_branches.empty()) {
    return false;
  }

  llvm::DominatorTree doms(func);
  std::vector<std::pair<llvm::Use *, llvm::Value *>> replacements;

  // Go find all uses of the `select` that are dominated by one of the edges
  // flowing out of the branch.
  for (auto [sel, br] : select_branches) {
    llvm::BasicBlockEdge taken_edge(br->getParent(), br->getSuccessor(0));
    llvm::BasicBlockEdge not_taken_edge(br->getParent(), br->getSuccessor(1));

    const auto true_val = sel->getTrueValue();
    const auto false_val = sel->getFalseValue();

    for (auto &sel_use : sel->uses()) {
      if (doms.dominates(taken_edge, sel_use)) {
        replacements.emplace_back(&sel_use, true_val);
      } else if (doms.dominates(not_taken_edge, sel_use)) {
        replacements.emplace_back(&sel_use, false_val);
      }
    }
  }

  // Apply any replacements, thereby sinking the selected values at their
  // usage sites.
  for (auto [use_of_select, selected_val_to_sink] : replacements) {
    use_of_select->set(selected_val_to_sink);
  }

  // Clean up the unneeded selects.
  for (auto [sel, br] : select_branches) {
    if (sel->use_empty()) {
      sel->eraseFromParent();
    }
  }

  return !replacements.empty();
}

}  // namespace

// When lifting conditional control-flow, we end up with the following pattern:
//
//        %25 = icmp eq i8 %24, 0
//        %26 = select i1 %25, i64 TAKEN_PC, i64 NOT_TAKEN_PC
//        br i1 %25, label %27, label %34
//
//        27:
//        ... use of %26
//
//        34:
//        ... use of %26
//
// This function pass transforms the above pattern into the following:
//
//        %25 = icmp eq i8 %24, 0
//        br i1 %25, label %27, label %34
//
//        27:
//        ... use of TAKEN_PC
//
//        34:
//        ... use of NOT_TAKEN_PC
//
// When this happens, we're better able to fold cross-references at the targets
// of conditional branches.
llvm::FunctionPass *CreateSinkSelectionsIntoBranchTargets(void) {
  return new SinkSelectionsIntoBranchTargets;
}

}  // namespace anvill
