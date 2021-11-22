/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

//
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
//

#pragma once

#include <unordered_map>

#include "BaseFunctionPass.h"

namespace anvill {

class SinkSelectionsIntoBranchTargets final
    : public BaseFunctionPass<SinkSelectionsIntoBranchTargets> {

 public:
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

  // Identifies all `select` instructions in `function`, where the `SelectInst`
  // shares the same condition as a conditional branch.
  static FunctionAnalysis AnalyzeFunction(llvm::Function &function);

  // Applies the transformation that moves the `SelectInst` instructions
  // inside each branch
  static void SinkSelectInstructions(const FunctionAnalysis &analysis);

  // Creates a new SinkSelectionsIntoBranchTargets object
  static SinkSelectionsIntoBranchTargets *
  Create(ITransformationErrorManager &error_manager);

  // Function pass entry point
  bool Run(llvm::Function &function, llvm::FunctionAnalysisManager &fam);

  // Returns the pass name
  static llvm::StringRef name(void);

  SinkSelectionsIntoBranchTargets(ITransformationErrorManager &error_manager);
  ~SinkSelectionsIntoBranchTargets(void) override = default;
};

}  // namespace anvill
