/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <llvm/IR/Dominators.h>

#include "BaseFunctionPass.h"

namespace anvill {


class InstructionFolderPass final
    : public BaseFunctionPass<InstructionFolderPass> {
 public:
  explicit InstructionFolderPass(ITransformationErrorManager &error_manager);

  ~InstructionFolderPass(void) override = default;

  // Function pass entry point
  bool Run(llvm::Function &function, llvm::FunctionAnalysisManager &fam);

  // Returns the pass name
  static llvm::StringRef name(void);


  // A single incoming value + basic_block for a PHI node
  struct IncomingValue final {
    llvm::BasicBlock *basic_block{nullptr};
    llvm::Value *value{nullptr};
  };

  // A list of incoming values for a PHI node
  using IncomingValueList = std::vector<IncomingValue>;

  // This structure describes an instruction replacement
  struct InstructionReplacement final {
    llvm::Instruction *original_instr{nullptr};
    llvm::Instruction *replacement_instr{nullptr};
  };

  // A list of instruction replacements to perform at the end of
  // a folding procedure
  using InstructionReplacementList = std::vector<InstructionReplacement>;

  // Performs instruction replacements according to the given list, removing the
  // dropping all the instructions that are no longer needed
  static void PerformInstructionReplacements(
      const InstructionReplacementList &replacement_list);


  // Before we can fold a `GetElementPtrInst` instruction, we have to
  // collect the indices. This function will do the work, and return
  // false if any of them makes the folding not possible
  static bool
  CollectAndValidateGEPIndexes(std::vector<llvm::Value *> &index_list,
                               llvm::Instruction *phi_or_select_instr,
                               llvm::Instruction *gep_instr);


  class PassFunctionState {
   private:
    const llvm::DominatorTreeAnalysis::Result &dt;

   public:
    PassFunctionState(const llvm::DominatorTreeAnalysis::Result &dt) : dt(dt) {}

    // Folds `Select` instructions interacting with `CastInst`,
    // `BinaryOperator` and `GetElementPtrInst` instructions
    //
    // Returns true if the function was changed
    bool FoldSelectInstruction(InstructionList &output,
                               llvm::Instruction *instr);

    // Folds `PHINode` instructions interacting with `CastInst`,
    // `BinaryOperator` and `GetElementPtrInst` instructions
    //
    // Returns true if the function was changed
    bool FoldPHINode(InstructionList &output, llvm::Instruction *instr);


    // Folders for
    //   `SelectInst` + `BinaryOperator`
    //   `PHINode` + `BinaryOperator`
    //
    //   src:
    //     x = select cond, true_value, false_value ; (or PHI)
    //     y = add z, x
    //
    //   dst
    //     y = select cond, (add z, true_value), (add z, false_value) ; (or PHI)
    //
    static bool FoldSelectWithBinaryOp(llvm::Instruction *&output,
                                       llvm::Instruction *select_instr,
                                       llvm::Value *condition,
                                       llvm::Value *true_value,
                                       llvm::Value *false_value,
                                       llvm::Instruction *binary_op_instr);

    bool FoldPHINodeWithBinaryOp(llvm::Instruction *&output,
                                 llvm::Instruction *phi_node,
                                 IncomingValueList &incoming_values,
                                 llvm::Instruction *binary_op_instr);


    // Folders for
    //   `SelectInst` + `CastInst`
    //   `PHINode` + `CastInst`
    //
    //   src:
    //     x = select cond, true_value, false_value ; (or PHI)
    //     y = inttoptr x
    //
    //   dst
    //     new_true_value = inttoptr true_value
    //     new_false_value = inttoptr false_value
    //     y = select cond, new_true_value, new_false_value ; (or PHI)
    //
    static bool FoldSelectWithCastInst(llvm::Instruction *&output,
                                       llvm::Instruction *select_instr,
                                       llvm::Value *condition,
                                       llvm::Value *true_value,
                                       llvm::Value *false_value,
                                       llvm::Instruction *cast_instr);

    bool FoldPHINodeWithCastInst(llvm::Instruction *&output,
                                 llvm::Instruction *phi_node,
                                 IncomingValueList &incoming_values,
                                 llvm::Instruction *cast_instr);

    // Folders for
    //   `SelectInst` + `GetElementPtrInst`
    //   `PHINode` + `GetElementPtrInst`
    //
    //   src:
    //     x = select cond, true_value, false_value ; (or PHI)
    //     y = getelementptr x [indexes]
    //
    //   dst
    //     new_true_value = getelementptr true_value [indexes]
    //     new_false_value = getelementptr false_value [indexes]
    //     y = select cond, new_true_value, new_false_value ; (or PHI)
    //
    static bool FoldSelectWithGEPInst(llvm::Instruction *&output,
                                      llvm::Instruction *select_instr,
                                      llvm::Value *condition,
                                      llvm::Value *true_value,
                                      llvm::Value *false_value,
                                      llvm::Instruction *gep_instr);

    bool FoldPHINodeWithGEPInst(llvm::Instruction *&output,
                                llvm::Instruction *phi_node,
                                IncomingValueList &incoming_values,
                                llvm::Instruction *cast_instr);
  };
};

}  // namespace anvill
