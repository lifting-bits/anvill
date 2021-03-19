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

#include "InstructionFolderPass.h"

#include <iostream>
#include <magic_enum.hpp>
#include <unordered_map>
#include <unordered_set>

namespace anvill {

namespace {

//
// Instruction folders; these will match first_instr_type -> second_instr_type
// and call the corresponding callback to attempt the fold operation
//

using InstructionFolder = bool (*)(InstructionFolderPass::InstructionList &,
                                   llvm::Instruction *);

// clang-format off
const std::unordered_map<std::uint32_t, InstructionFolder> kInstructionFolderMap = {
  { llvm::Instruction::Select, InstructionFolderPass::FoldSelectInstruction },
  { llvm::Instruction::PHI, InstructionFolderPass::FoldPHINode },
};
// clang-format on

//
// Case handlers for `SelectInst` instructions
//

using SelectInstructionFolder = bool (*)(llvm::Instruction *&output,
                                         llvm::Instruction *, llvm::Value *,
                                         llvm::Value *, llvm::Value *,
                                         llvm::Instruction *);

// clang-format off
const std::unordered_map<std::uint32_t, SelectInstructionFolder> kSelectInstructionFolderMap = {
  // Binary operators
  { llvm::Instruction::Add, InstructionFolderPass::FoldSelectWithBinaryOp },
  { llvm::Instruction::FAdd, InstructionFolderPass::FoldSelectWithBinaryOp },
  { llvm::Instruction::Sub, InstructionFolderPass::FoldSelectWithBinaryOp },
  { llvm::Instruction::FSub, InstructionFolderPass::FoldSelectWithBinaryOp },
  { llvm::Instruction::Mul, InstructionFolderPass::FoldSelectWithBinaryOp },
  { llvm::Instruction::FMul, InstructionFolderPass::FoldSelectWithBinaryOp },
  { llvm::Instruction::UDiv, InstructionFolderPass::FoldSelectWithBinaryOp },
  { llvm::Instruction::SDiv, InstructionFolderPass::FoldSelectWithBinaryOp },
  { llvm::Instruction::FDiv, InstructionFolderPass::FoldSelectWithBinaryOp },
  { llvm::Instruction::URem, InstructionFolderPass::FoldSelectWithBinaryOp },
  { llvm::Instruction::SRem, InstructionFolderPass::FoldSelectWithBinaryOp },
  { llvm::Instruction::FRem, InstructionFolderPass::FoldSelectWithBinaryOp },
  { llvm::Instruction::Shl, InstructionFolderPass::FoldSelectWithBinaryOp },
  { llvm::Instruction::LShr, InstructionFolderPass::FoldSelectWithBinaryOp },
  { llvm::Instruction::AShr, InstructionFolderPass::FoldSelectWithBinaryOp },
  { llvm::Instruction::And, InstructionFolderPass::FoldSelectWithBinaryOp },
  { llvm::Instruction::Or, InstructionFolderPass::FoldSelectWithBinaryOp },
  { llvm::Instruction::Xor, InstructionFolderPass::FoldSelectWithBinaryOp },

  // Cast operators
  { llvm::Instruction::Trunc, InstructionFolderPass::FoldSelectWithCastInst },
  { llvm::Instruction::ZExt, InstructionFolderPass::FoldSelectWithCastInst },
  { llvm::Instruction::SExt, InstructionFolderPass::FoldSelectWithCastInst },
  { llvm::Instruction::FPToUI, InstructionFolderPass::FoldSelectWithCastInst },
  { llvm::Instruction::FPToSI, InstructionFolderPass::FoldSelectWithCastInst },
  { llvm::Instruction::UIToFP, InstructionFolderPass::FoldSelectWithCastInst },
  { llvm::Instruction::SIToFP, InstructionFolderPass::FoldSelectWithCastInst },
  { llvm::Instruction::FPTrunc, InstructionFolderPass::FoldSelectWithCastInst },
  { llvm::Instruction::FPExt, InstructionFolderPass::FoldSelectWithCastInst },
  { llvm::Instruction::PtrToInt, InstructionFolderPass::FoldSelectWithCastInst },
  { llvm::Instruction::IntToPtr, InstructionFolderPass::FoldSelectWithCastInst },
  { llvm::Instruction::BitCast, InstructionFolderPass::FoldSelectWithCastInst },

  // Memory operators
  { llvm::Instruction::GetElementPtr, InstructionFolderPass::FoldSelectWithGEPInst },
};
// clang-format on

//
// Case handlers for `PHINode` instructions
//

using PHINodeInstructionFolder =
    bool (*)(llvm::Instruction *&output, llvm::Instruction *,
             InstructionFolderPass::IncomingValueList &, llvm::Instruction *);

// clang-format off
const std::unordered_map<std::uint32_t, PHINodeInstructionFolder> kPHINodeFolderMap = {
  // Binary operators
  { llvm::Instruction::Add, InstructionFolderPass::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::FAdd, InstructionFolderPass::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::Sub, InstructionFolderPass::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::FSub, InstructionFolderPass::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::Mul, InstructionFolderPass::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::FMul, InstructionFolderPass::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::UDiv, InstructionFolderPass::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::SDiv, InstructionFolderPass::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::FDiv, InstructionFolderPass::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::URem, InstructionFolderPass::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::SRem, InstructionFolderPass::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::FRem, InstructionFolderPass::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::Shl, InstructionFolderPass::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::LShr, InstructionFolderPass::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::AShr, InstructionFolderPass::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::And, InstructionFolderPass::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::Or, InstructionFolderPass::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::Xor, InstructionFolderPass::FoldPHINodeWithBinaryOp },

  // Cast operators
  { llvm::Instruction::Trunc, InstructionFolderPass::FoldPHINodeWithCastInst },
  { llvm::Instruction::ZExt, InstructionFolderPass::FoldPHINodeWithCastInst },
  { llvm::Instruction::SExt, InstructionFolderPass::FoldPHINodeWithCastInst },
  { llvm::Instruction::FPToUI, InstructionFolderPass::FoldPHINodeWithCastInst },
  { llvm::Instruction::FPToSI, InstructionFolderPass::FoldPHINodeWithCastInst },
  { llvm::Instruction::UIToFP, InstructionFolderPass::FoldPHINodeWithCastInst },
  { llvm::Instruction::SIToFP, InstructionFolderPass::FoldPHINodeWithCastInst },
  { llvm::Instruction::FPTrunc, InstructionFolderPass::FoldPHINodeWithCastInst },
  { llvm::Instruction::FPExt, InstructionFolderPass::FoldPHINodeWithCastInst },
  { llvm::Instruction::PtrToInt, InstructionFolderPass::FoldPHINodeWithCastInst },
  { llvm::Instruction::IntToPtr, InstructionFolderPass::FoldPHINodeWithCastInst },
  { llvm::Instruction::BitCast, InstructionFolderPass::FoldPHINodeWithCastInst },

  // Memory operators
  { llvm::Instruction::GetElementPtr, InstructionFolderPass::FoldPHINodeWithGEPInst },
};
// clang-format on

}  // namespace

InstructionFolderPass::InstructionFolderPass(
    ITransformationErrorManager &error_manager, const LifterOptions &options)
    : BaseFunctionPass(error_manager),
      options(options) {}


InstructionFolderPass *
InstructionFolderPass::Create(ITransformationErrorManager &error_manager,
                              const LifterOptions &options) {
  return new InstructionFolderPass(error_manager, options);
}

bool InstructionFolderPass::Run(llvm::Function &function) {
  if (function.isDeclaration()) {
    return false;
  }

  // Create an initial queue of possible candidates
  auto next_worklist =
      SelectInstructions<llvm::SelectInst, llvm::PHINode>(function);

  std::unordered_set<llvm::Instruction *> visited_instructions;

  // Go through the list of discovered instructions
  InstructionList worklist;
  bool function_changed{false};

  while (!next_worklist.empty()) {
    worklist.swap(next_worklist);
    next_worklist.clear();

    for (auto instr : worklist) {
      // Keep track of the instructions we have visited so we don't
      // loop forever
      if (visited_instructions.count(instr) != 0U) {
        continue;
      }

      visited_instructions.insert(instr);

      // Attempt to combine this instruction
      auto instr_folder_it = kInstructionFolderMap.find(instr->getOpcode());
      if (instr_folder_it != kInstructionFolderMap.end()) {
        const auto &instr_folder = instr_folder_it->second;
        if (instr_folder(next_worklist, instr)) {
          function_changed = true;
        }
      }
    }
  }

  return function_changed;
}

llvm::StringRef InstructionFolderPass::getPassName(void) const {
  return llvm::StringRef("InstructionFolderPass");
}

bool InstructionFolderPass::FoldSelectInstruction(
    InstructionFolderPass::InstructionList &output, llvm::Instruction *instr) {

  // Extract the condition and the two operands for later
  llvm::Value *condition{nullptr};
  llvm::Value *true_value{nullptr};
  llvm::Value *false_value{nullptr};

  {
    auto select_instr = llvm::dyn_cast<llvm::SelectInst>(instr);

    condition = select_instr->getCondition();
    true_value = select_instr->getTrueValue();
    false_value = select_instr->getFalseValue();
  }

  // Since we are iterating over the users, we have to postpone
  // the deletion after the loop
  InstructionList replaced_instr_list;

  // Go through all the users of this `select` instruction
  for (auto user : instr->users()) {
    auto user_instr = llvm::dyn_cast<llvm::Instruction>(user);

    // Search for a function that knows how to handle this case
    auto instr_folder_it =
        kSelectInstructionFolderMap.find(user_instr->getOpcode());

    if (instr_folder_it == kSelectInstructionFolderMap.end()) {
      continue;
    }

    const auto &instr_folder = instr_folder_it->second;

    // If we succeed in folding this instruction, then also perform
    // the replacement and the required cleanup
    llvm::Instruction *replacement{nullptr};
    if (!instr_folder(replacement, instr, condition, true_value, false_value,
                      user_instr)) {
      continue;
    }


    for (auto &use : user_instr->uses()) {
      use.set(replacement);
    }

    replaced_instr_list.push_back(user_instr);
    output.push_back(replacement);
  }

  // Finally, drop all the instructions we no longer need
  auto function_changed = !replaced_instr_list.empty();

  for (auto replaced_instr : replaced_instr_list) {
    if (replaced_instr->getNumUses() == 0U) {
      replaced_instr->eraseFromParent();
    }
  }

  if (instr->getNumUses() == 0U) {
    instr->eraseFromParent();
  }

  return function_changed;
}

bool InstructionFolderPass::FoldPHINode(
    InstructionFolderPass::InstructionList &output, llvm::Instruction *instr) {

  // Extract the incoming values
  IncomingValueList incoming_value_list;

  {
    auto phi_node = llvm::dyn_cast<llvm::PHINode>(instr);

    auto incoming_value_count = phi_node->getNumIncomingValues();

    for (auto i = 0U; i < incoming_value_count; ++i) {
      IncomingValue incoming_value;
      incoming_value.value = phi_node->getIncomingValue(i);
      incoming_value.basic_block = phi_node->getIncomingBlock(i);

      incoming_value_list.push_back(std::move(incoming_value));
    }
  }

  // Since we are iterating over the users, we have to postpone
  // the deletion after the loop
  InstructionList replaced_instr_list;

  // Go through all the users of this `select` instruction
  for (auto user : instr->users()) {
    auto user_instr = llvm::dyn_cast<llvm::Instruction>(user);

    // Search for a function that knows how to handle this case
    auto instr_folder_it = kPHINodeFolderMap.find(user_instr->getOpcode());
    if (instr_folder_it == kPHINodeFolderMap.end()) {
      continue;
    }

    const auto &instr_folder = instr_folder_it->second;

    // If we succeed in folding this instruction, then also perform
    // the replacement and the required cleanup
    llvm::Instruction *replacement{nullptr};
    if (!instr_folder(replacement, instr, incoming_value_list, user_instr)) {
      continue;
    }

    for (auto &use : user_instr->uses()) {
      use.set(replacement);
    }

    replaced_instr_list.push_back(user_instr);
    output.push_back(replacement);
  }

  // Finally, drop all the instructions we no longer need
  auto function_changed = !replaced_instr_list.empty();

  for (auto replaced_instr : replaced_instr_list) {
    if (replaced_instr->getNumUses() == 0U) {
      replaced_instr->eraseFromParent();
    }
  }

  if (instr->getNumUses() == 0U) {
    instr->eraseFromParent();
  }

  for (auto &incoming_value : incoming_value_list) {
    auto value_as_instr =
        llvm::dyn_cast<llvm::Instruction>(incoming_value.value);
    if (value_as_instr == nullptr) {
      continue;
    }

    if (value_as_instr->getNumUses() == 0U) {
      value_as_instr->eraseFromParent();
    }
  }

  return function_changed;
}

bool InstructionFolderPass::FoldSelectWithBinaryOp(
    llvm::Instruction *&output, llvm::Instruction *select_instr,
    llvm::Value *condition, llvm::Value *true_value, llvm::Value *false_value,
    llvm::Instruction *binary_op_instr) {

  // This binary operator is using our `select` instruction. Take the
  // operand on the opposite side
  auto operand = binary_op_instr->getOperand(0U);
  if (operand == select_instr) {
    operand = binary_op_instr->getOperand(1U);
  }

  // In order to be able to combine these two instructions, the
  // other operand needs to be a constant
  if (!(llvm::isa<llvm::Constant>(operand) &&
        llvm::isa<llvm::ConstantExpr>(operand))) {
    return false;
  }

  // Finally, rewrite the instructions
  llvm::IRBuilder<> builder(binary_op_instr);

  auto opcode =
      llvm::dyn_cast<llvm::BinaryOperator>(binary_op_instr)->getOpcode();

  auto new_true_value = builder.CreateBinOp(opcode, true_value, operand);
  auto new_false_value = builder.CreateBinOp(opcode, false_value, operand);

  auto replacement =
      builder.CreateSelect(condition, new_true_value, new_false_value);

  output = llvm::dyn_cast<llvm::Instruction>(replacement);
  return true;
}

bool InstructionFolderPass::FoldPHINodeWithBinaryOp(
    llvm::Instruction *&output, llvm::Instruction *phi_node,
    InstructionFolderPass::IncomingValueList &incoming_values,
    llvm::Instruction *binary_op_instr) {

  // This binary operator is using our `PHINode` instruction. Take the
  // operand on the opposite side
  auto operand = binary_op_instr->getOperand(0U);
  if (operand == phi_node) {
    operand = binary_op_instr->getOperand(1U);
  }

  // In order to be able to combine these two instructions, the
  // other operand needs to be a constant
  if (!(llvm::isa<llvm::Constant>(operand) &&
        llvm::isa<llvm::ConstantExpr>(operand))) {
    return false;
  }

  // Get the binary operator opcode for later
  auto opcode =
      llvm::dyn_cast<llvm::BinaryOperator>(binary_op_instr)->getOpcode();

  // Go through each incoming value, and try to push the binary operator
  // on the other side of the PHI node
  IncomingValueList new_incoming_values;

  for (auto &incoming_value : incoming_values) {
    // Set the builder inside the incoming block
    llvm::IRBuilder<> builder(incoming_value.basic_block->getTerminator());

    IncomingValue new_incoming_value;
    new_incoming_value.value =
        builder.CreateBinOp(opcode, incoming_value.value, operand);
    new_incoming_value.basic_block = incoming_value.basic_block;
    new_incoming_values.push_back(std::move(new_incoming_value));
  }

  // Move back to the current block, then rewrite the phi node
  llvm::IRBuilder<> builder(phi_node);

  auto new_phi_node =
      builder.CreatePHI(phi_node->getType(), new_incoming_values.size());

  for (auto &new_incoming_value : new_incoming_values) {
    new_phi_node->addIncoming(new_incoming_value.value,
                              new_incoming_value.basic_block);
  }

  output = llvm::dyn_cast<llvm::Instruction>(new_phi_node);
  return true;
}

bool InstructionFolderPass::FoldSelectWithCastInst(
    llvm::Instruction *&output, llvm::Instruction *select_instr,
    llvm::Value *condition, llvm::Value *true_value, llvm::Value *false_value,
    llvm::Instruction *cast_instr) {

  llvm::Instruction::CastOps cast_opcode{};
  llvm::Type *destination_type{};

  {
    auto instr = llvm::dyn_cast<llvm::CastInst>(cast_instr);

    cast_opcode = instr->getOpcode();
    destination_type = instr->getDestTy();
  }

  llvm::IRBuilder<> builder(cast_instr);

  auto new_true_value =
      builder.CreateCast(cast_opcode, true_value, destination_type);

  auto new_false_value =
      builder.CreateCast(cast_opcode, false_value, destination_type);

  auto replacement =
      builder.CreateSelect(condition, new_true_value, new_false_value);

  output = llvm::dyn_cast<llvm::Instruction>(replacement);
  return true;
}

bool InstructionFolderPass::FoldPHINodeWithCastInst(
    llvm::Instruction *&output, llvm::Instruction *phi_node,
    InstructionFolderPass::IncomingValueList &incoming_values,
    llvm::Instruction *cast_instr) {

  llvm::Instruction::CastOps cast_opcode{};
  llvm::Type *destination_type{};

  {
    auto instr = llvm::dyn_cast<llvm::CastInst>(cast_instr);

    cast_opcode = instr->getOpcode();
    destination_type = instr->getDestTy();
  }

  // Go through each incoming value, and try to push the cast operator
  // on the other side of the PHI node
  IncomingValueList new_incoming_values;

  for (auto &incoming_value : incoming_values) {
    // Set the builder inside the incoming block
    llvm::IRBuilder<> builder(incoming_value.basic_block->getTerminator());

    IncomingValue new_incoming_value;
    new_incoming_value.value =
        builder.CreateCast(cast_opcode, incoming_value.value, destination_type);
    new_incoming_value.basic_block = incoming_value.basic_block;
    new_incoming_values.push_back(std::move(new_incoming_value));
  }

  // Move back to the current block, then rewrite the phi node; since
  // we changed the type on the other side, make sure to update it here
  // as well
  llvm::IRBuilder<> builder(phi_node);

  auto new_phi_node =
      builder.CreatePHI(destination_type, new_incoming_values.size());

  for (auto &new_incoming_value : new_incoming_values) {
    new_phi_node->addIncoming(new_incoming_value.value,
                              new_incoming_value.basic_block);
  }

  output = llvm::dyn_cast<llvm::Instruction>(new_phi_node);
  return true;
}

bool InstructionFolderPass::FoldSelectWithGEPInst(
    llvm::Instruction *&output, llvm::Instruction *select_instr,
    llvm::Value *condition, llvm::Value *true_value, llvm::Value *false_value,
    llvm::Instruction *gep_instr) {

  // Acquire all the indices first, and make sure that they
  // are all constant values
  std::vector<llvm::Value *> index_list;

  {
    auto instr = llvm::dyn_cast<llvm::GetElementPtrInst>(gep_instr);
    if (!instr->hasAllConstantIndices()) {
      return false;
    }

    for (auto &index : instr->indices()) {
      index_list.push_back(index);
    }
  }

  llvm::IRBuilder<> builder(gep_instr);

  auto new_true_value = builder.CreateGEP(true_value, index_list);
  auto new_false_value = builder.CreateGEP(false_value, index_list);

  auto replacement =
      builder.CreateSelect(condition, new_true_value, new_false_value);

  output = llvm::dyn_cast<llvm::Instruction>(replacement);
  return true;
}

bool InstructionFolderPass::FoldPHINodeWithGEPInst(
    llvm::Instruction *&output, llvm::Instruction *phi_node,
    InstructionFolderPass::IncomingValueList &incoming_values,
    llvm::Instruction *gep_instr) {

  // Acquire all the indices first, so we can verify them:
  // 1. If they are instructions, then all the indices in the GEP
  //    that are preceding our PHI use must NOT reside in the same
  //    basic block as the GEP (otherwise we won't have them when
  //    we move the GetElementPtrInst inside the incoming basic block)
  // 2. All the indices that are following the PHI use must be constants
  std::vector<llvm::Value *> index_list;

  {
    auto instr = llvm::dyn_cast<llvm::GetElementPtrInst>(gep_instr);
    bool phi_index_found{false};

    for (auto &index : instr->indices()) {
      index_list.push_back(index);

      // If this is our PHI node, update the verification stage and skip
      // any check
      auto index_as_instr = llvm::dyn_cast<llvm::Instruction>(&index);
      if (index_as_instr == phi_node) {
        phi_index_found = true;
        continue;
      }

      if (!phi_index_found) {
        // We have not met the PHI index yet, make sure that this
        // index is still reachable if we move the GEP
        if (index_as_instr != nullptr &&
            index_as_instr->getParent() == gep_instr->getParent()) {
          return false;
        }

      } else {
        // We are after the PHI index; make sure that this value is a
        // constant
        if (!(llvm::isa<llvm::Constant>(index) &&
              llvm::isa<llvm::ConstantExpr>(index))) {
          return false;
        }
      }
    }
  }

  // Go through each incoming value and move the `GetElementPtrInst`
  // instruction on each incoming basic block
  IncomingValueList new_incoming_values;

  for (auto &incoming_value : incoming_values) {
    // Set the builder inside the incoming block
    llvm::IRBuilder<> builder(incoming_value.basic_block->getTerminator());

    IncomingValue new_incoming_value;
    new_incoming_value.value =
        builder.CreateGEP(incoming_value.value, index_list);

    new_incoming_value.basic_block = incoming_value.basic_block;
    new_incoming_values.push_back(std::move(new_incoming_value));
  }

  // Move back to the current block, then rewrite the phi node; on this
  // side, we have to use the type returned by the GEP instruction
  llvm::IRBuilder<> builder(phi_node);

  auto new_phi_node =
      builder.CreatePHI(gep_instr->getType(), new_incoming_values.size());

  for (auto &new_incoming_value : new_incoming_values) {
    new_phi_node->addIncoming(new_incoming_value.value,
                              new_incoming_value.basic_block);
  }

  output = llvm::dyn_cast<llvm::Instruction>(new_phi_node);
  return true;
}

llvm::FunctionPass *
CreateInstructionFolderPass(ITransformationErrorManager &error_manager,
                            const LifterOptions &options) {
  return InstructionFolderPass::Create(error_manager, options);
}

}  // namespace anvill
