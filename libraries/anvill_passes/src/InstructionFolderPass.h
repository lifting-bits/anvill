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

#pragma once

#include <anvill/Lifters/Options.h>

#include "BaseFunctionPass.h"

namespace anvill {

class InstructionFolderPass final
    : public BaseFunctionPass<InstructionFolderPass> {
  // Lifting options
  const LifterOptions &options;

 public:
  InstructionFolderPass(ITransformationErrorManager &error_manager,
                        const LifterOptions &options);

  virtual ~InstructionFolderPass(void) override = default;

  // Creates a new InstructionFolderPass object
  static InstructionFolderPass *
  Create(ITransformationErrorManager &error_manager,
         const LifterOptions &options);

  // Function pass entry point
  bool Run(llvm::Function &function);

  // Returns the pass name
  virtual llvm::StringRef getPassName(void) const override;

  // Folds `Select` instructions interacting with `CastInst`,
  // `BinaryOperator` and `GetElementPtrInst` instructions
  //
  // Returns true if the function was changed
  static bool FoldSelectInstruction(InstructionList &output,
                                    llvm::Instruction *instr);

  // A single incoming value + basic_block for a PHI node
  struct IncomingValue final {
    llvm::BasicBlock *basic_block{nullptr};
    llvm::Value *value{nullptr};
  };

  // A list of incoming values for a PHI node
  using IncomingValueList = std::vector<IncomingValue>;

  // Folds `PHINode` instructions interacting with `CastInst`,
  // `BinaryOperator` and `GetElementPtrInst` instructions
  //
  // Returns true if the function was changed
  static bool FoldPHINode(InstructionList &output, llvm::Instruction *instr);

  // Folders for
  //   `SelectInst` + `BinaryOperator`
  //   `PHINode` + `BinaryOperator`
  //
  //   src:
  //     x = select cond, true_value, false_value
  //     y = add z, x
  //
  //   dst
  //     y = select cond, (add z, true_value), (add z, false_value)
  //
  static bool FoldSelectWithBinaryOp(llvm::Instruction *&output,
                                     llvm::Instruction *select_instr,
                                     llvm::Value *condition,
                                     llvm::Value *true_value,
                                     llvm::Value *false_value,
                                     llvm::Instruction *binary_op_instr);

  static bool FoldPHINodeWithBinaryOp(llvm::Instruction *&output,
                                      llvm::Instruction *phi_node,
                                      IncomingValueList &incoming_values,
                                      llvm::Instruction *binary_op_instr);

  // Folders for
  //   `SelectInst` + `CastInst`
  //   `PHINode` + `CastInst`
  //
  //   src:
  //     x = select cond, true_value, false_value
  //     y = inttoptr x
  //
  //   dst
  //     new_true_value = inttoptr true_value
  //     new_false_value = inttoptr false_value
  //     y = select cond, new_true_value, new_false_value
  //
  static bool FoldSelectWithCastInst(llvm::Instruction *&output,
                                     llvm::Instruction *select_instr,
                                     llvm::Value *condition,
                                     llvm::Value *true_value,
                                     llvm::Value *false_value,
                                     llvm::Instruction *cast_instr);

  static bool FoldPHINodeWithCastInst(llvm::Instruction *&output,
                                      llvm::Instruction *phi_node,
                                      IncomingValueList &incoming_values,
                                      llvm::Instruction *cast_instr);

  // Folders for
  //   `SelectInst` + `GetElementPtrInst`
  //   `PHINode` + `GetElementPtrInst`
  //
  //   src:
  //     x = select cond, true_value, false_value
  //     y = getelementptr x [indexes]
  //
  //   dst
  //     new_true_value = getelementptr true_value [indexes]
  //     new_false_value = getelementptr false_value [indexes]
  //     y = select cond, new_true_value, new_false_value
  //
  static bool
  FoldSelectWithGEPInst(llvm::Instruction *&output,
                        llvm::Instruction *select_instr, llvm::Value *condition,
                        llvm::Value *true_value, llvm::Value *false_value,
                        llvm::Instruction *gep_instr);

  static bool FoldPHINodeWithGEPInst(llvm::Instruction *&output,
                                     llvm::Instruction *phi_node,
                                     IncomingValueList &incoming_values,
                                     llvm::Instruction *cast_instr);
};

}  // namespace anvill
