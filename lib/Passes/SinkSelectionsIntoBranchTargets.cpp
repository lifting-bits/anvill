/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Passes/SinkSelectionsIntoBranchTargets.h>

#include <anvill/Transforms.h>
#include <anvill/Utils.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>

#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "Utils.h"

namespace anvill {
namespace {

using BranchList = std::vector<llvm::BranchInst *>;

using SelectListMap = std::unordered_map<llvm::SelectInst *, BranchList>;

struct FunctionAnalysis final {
  struct Replacement final {
    llvm::Use *use_to_replace{nullptr};
    llvm::Value *replace_with{nullptr};
  };

  using ReplacementList = std::vector<Replacement>;
  using DisposableInstructionList = std::unordered_set<llvm::SelectInst *>;

  ReplacementList replacement_list;
  DisposableInstructionList disposable_instruction_list;
};

static FunctionAnalysis AnalyzeFunction(
    const llvm::DominatorTreeAnalysis::Result &dt, llvm::Function &function) {

  // Collect all the applicable instructions
  SelectListMap select_list_map;

  for (auto &instruction : llvm::instructions(function)) {

    // Look for `SelectInst` instructions
    auto select_inst = llvm::dyn_cast<llvm::SelectInst>(&instruction);
    if (select_inst == nullptr) {
      continue;
    }

    const auto select_condition = select_inst->getCondition();

    for (auto &use : select_condition->uses()) {

      // Look for users that are conditional branches
      const auto branch_inst = llvm::dyn_cast<llvm::BranchInst>(use.getUser());
      if (branch_inst == nullptr) {
        continue;
      }

      if (!branch_inst->isConditional()) {
        continue;
      }

      // The `SelectInst` and `BranchInst` must share the same
      // condition
      if (branch_inst->getCondition() != select_condition) {
        continue;
      }

      auto select_list_it = select_list_map.find(select_inst);
      if (select_list_it == select_list_map.end()) {
        auto insert_status = select_list_map.insert({select_inst, {}});
        select_list_it = insert_status.first;
      }

      auto &branch_list = select_list_it->second;
      branch_list.emplace_back(branch_inst);
    }
  }

  // Determine which replacements need to happen
  FunctionAnalysis output;


  for (auto &select_list_map_p : select_list_map) {
    auto select_inst = select_list_map_p.first;
    auto &branch_list = select_list_map_p.second;

    for (auto branch : branch_list) {
      llvm::BasicBlockEdge taken_edge(branch->getParent(),
                                      branch->getSuccessor(0));

      llvm::BasicBlockEdge not_taken_edge(branch->getParent(),
                                          branch->getSuccessor(1));

      const auto true_val = select_inst->getTrueValue();
      const auto false_val = select_inst->getFalseValue();

      for (auto &select_inst_use : select_inst->uses()) {
        FunctionAnalysis::Replacement replacement;
        replacement.use_to_replace = &select_inst_use;

        if (dt.dominates(taken_edge, select_inst_use)) {
          replacement.replace_with = true_val;

        } else if (dt.dominates(not_taken_edge, select_inst_use)) {
          replacement.replace_with = false_val;
        }

        if (replacement.replace_with == nullptr) {
          continue;
        }

        output.disposable_instruction_list.insert(select_inst);
        output.replacement_list.push_back(std::move(replacement));
      }
    }
  }

  return output;
}

static bool SinkSelectInstructions(const FunctionAnalysis &analysis) {

  auto changed = false;
  for (const auto &replacement : analysis.replacement_list) {
    CopyMetadataTo(replacement.use_to_replace->get(), replacement.replace_with);
    replacement.use_to_replace->set(replacement.replace_with);
    changed = true;
  }

  for (auto select_inst : analysis.disposable_instruction_list) {
    if (select_inst->use_empty()) {
      select_inst->eraseFromParent();
      changed = true;
    }
  }

  return changed;
}

}  // namespace

llvm::PreservedAnalyses SinkSelectionsIntoBranchTargets::run(
    llvm::Function &function, llvm::FunctionAnalysisManager &fam) {
  if (function.isDeclaration()) {
    return llvm::PreservedAnalyses::all();
  }

  const auto &dt = fam.getResult<llvm::DominatorTreeAnalysis>(function);
  auto function_analysis = AnalyzeFunction(dt, function);
  if (function_analysis.replacement_list.empty()) {
    return llvm::PreservedAnalyses::all();
  }

  return ConvertBoolToPreserved(SinkSelectInstructions(function_analysis));
}

llvm::StringRef SinkSelectionsIntoBranchTargets::name(void) {
  return "SinkSelectionsIntoBranchTargets";
}

void AddSinkSelectionsIntoBranchTargets(
    llvm::FunctionPassManager &fpm) {
  fpm.addPass(SinkSelectionsIntoBranchTargets());
}

}  // namespace anvill
