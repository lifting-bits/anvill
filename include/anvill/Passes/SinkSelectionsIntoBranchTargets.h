/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <llvm/IR/PassManager.h>
#include <unordered_set>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Dominators.h>

namespace anvill {

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
class SinkSelectionsIntoBranchTargets final
    : public llvm::PassInfoMixin<SinkSelectionsIntoBranchTargets> {
 public:

  // Function pass entry point
  llvm::PreservedAnalyses run(llvm::Function &function,
                              llvm::FunctionAnalysisManager &fam);

  // Returns the pass name
  static llvm::StringRef name(void);

  static FunctionAnalysis AnalyzeFunction(const llvm::DominatorTreeAnalysis::Result &dt,llvm::Function &function);
};



}  // namespace anvill
