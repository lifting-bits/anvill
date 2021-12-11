/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Passes/HoistUsersOfSelectsAndPhis.h>

#include <anvill/Utils.h>
#include <cstdint>
#include <glog/logging.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IRBuilder.h>
#include <remill/BC/Util.h>

#include <map>
#include <unordered_map>
#include <unordered_set>

#include "Utils.h"

namespace anvill {
namespace {

// A single incoming value + basic_block for a PHI node
struct IncomingValue final {
  llvm::BasicBlock *basic_block{nullptr};
  llvm::Value *value{nullptr};

  inline bool operator<(const IncomingValue that) const {
    if (basic_block < that.basic_block) {
      return true;
    } else if (basic_block > that.basic_block) {
      return false;
    } else {
      return value < that.value;
    }
  }

  inline bool operator==(const IncomingValue that) const {
    return basic_block == that.basic_block &&
           value == that.value;
  }
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

}  // namespace

class HoistUsersOfSelectsAndPhis::PassFunctionState {
 private:
  const llvm::DominatorTreeAnalysis::Result &dt;

 public:
  inline PassFunctionState(const llvm::DominatorTreeAnalysis::Result &dt)
      : dt(dt) {}

  // Folds `Select` instructions interacting with `CastInst`,
  // `BinaryOperator` and `GetElementPtrInst` instructions
  //
  // Returns true if the function was changed
  bool FoldSelectInstruction(InstructionList &output,
                             llvm::SelectInst *instr);

  // Folds `PHINode` instructions interacting with `CastInst`,
  // `BinaryOperator` and `GetElementPtrInst` instructions
  //
  // Returns true if the function was changed
  bool FoldPHINode(InstructionList &output, llvm::PHINode *instr);

  bool FoldPHINodeWithBinaryOp(llvm::Instruction *&output,
                               llvm::PHINode *phi_node,
                               IncomingValueList &incoming_values,
                               llvm::Instruction *binary_op_instr);

  bool FoldPHINodeWithCastInst(llvm::Instruction *&output,
                               llvm::PHINode *phi_node,
                               IncomingValueList &incoming_values,
                               llvm::Instruction *cast_instr);

  bool FoldPHINodeWithGEPInst(llvm::Instruction *&output,
                              llvm::PHINode *phi_node,
                              IncomingValueList &incoming_values,
                              llvm::Instruction *cast_instr);
};

namespace {

// Case handlers for `SelectInst` instructions
using SelectInstructionFolder = bool (*)(llvm::Instruction *&output,
                                         llvm::Instruction *, llvm::Value *,
                                         llvm::Value *, llvm::Value *,
                                         llvm::Instruction *);

// Performs instruction replacements according to the given list, removing the
// dropping all the instructions that are no longer needed
static void PerformInstructionReplacements(
    const InstructionReplacementList &replacement_list) {
  for (const InstructionReplacement &repl : replacement_list) {
    repl.original_instr->replaceAllUsesWith(repl.replacement_instr);
    repl.original_instr->eraseFromParent();
  }
}

// Before we can fold a `GetElementPtrInst` instruction, we have to
// collect the indices. This function will do the work, and return
// false if any of them makes the folding not possible
static bool
CollectAndValidateGEPIndexes(std::vector<llvm::Value *> &index_list,
                             llvm::Instruction *phi_or_select_instr,
                             llvm::Instruction *gep_instr) {
  index_list.clear();

  // Acquire all the indices and verify them:
  // 1. If they are instructions, then all the indices in the GEP
  //    that are preceding our PHI/Select use must NOT reside in the same
  //    basic block as the GEP (otherwise we won't have them when
  //    we move the GetElementPtrInst inside the incoming basic block)
  // 2. All the indices that are following the PHI/Select use must be constants
  auto instr = llvm::dyn_cast<llvm::GetElementPtrInst>(gep_instr);
  bool phi_or_select_index_found{false};

  for (auto &index_use : instr->indices()) {
    auto index = index_use.get();
    index_list.push_back(index);

    // If this is our PHI/Select node, update the verification stage and skip
    // any check
    auto index_as_instr = llvm::dyn_cast<llvm::Instruction>(index);
    if (index_as_instr == phi_or_select_instr) {
      phi_or_select_index_found = true;
      continue;
    }

    if (!phi_or_select_index_found) {

      // We have not met the PHI/Select index yet, make sure that this
      // index is still reachable if we move the GEP
      if (index_as_instr != nullptr &&
          index_as_instr->getParent() == gep_instr->getParent()) {
        return false;
      }

    } else {

      // We are after the PHI/Select index; make sure that this value is a
      // constant
      if (!llvm::isa<llvm::Constant>(index)) {
        return false;
      }
    }
  }

  return true;
}

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
static bool FoldSelectWithBinaryOp(
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
  if (!llvm::isa<llvm::Constant>(operand)) {
    return false;
  }

  // Finally, rewrite the instructions
  llvm::IRBuilder<> builder(binary_op_instr);

  auto opcode =
      static_cast<llvm::Instruction::BinaryOps>(binary_op_instr->getOpcode());

  auto new_true_value = builder.CreateBinOp(opcode, true_value, operand);
  CopyMetadataTo(binary_op_instr, new_true_value);
  auto new_false_value = builder.CreateBinOp(opcode, false_value, operand);
  CopyMetadataTo(binary_op_instr, new_false_value);

  auto replacement =
      builder.CreateSelect(condition, new_true_value, new_false_value);
  CopyMetadataTo(select_instr, replacement);

  output = llvm::dyn_cast<llvm::Instruction>(replacement);
  return true;
}

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
static bool FoldSelectWithCastInst(
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

  // For vector select check if the condition element type is correct
  // and the number of elements in the condition type matches if the
  // destination type.
  auto should_fold = [](llvm::Type *condition_type,
                        llvm::Type *destination_type) {
    if (auto cond_vt = llvm::dyn_cast<llvm::VectorType>(condition_type)) {
      if (cond_vt->getElementType() !=
          llvm::Type::getInt1Ty(condition_type->getContext())) {
        return false;
      }

      if (auto dest_vt = llvm::dyn_cast<llvm::VectorType>(destination_type)) {
        if (dest_vt->getElementCount() == cond_vt->getElementCount()) {
          return true;
        }
      }
      return false;
    }

    return true;
  };

  if (!should_fold(condition->getType(), destination_type)) {
    return false;
  }

  llvm::IRBuilder<> builder(cast_instr);

  auto new_true_value =
      builder.CreateCast(cast_opcode, true_value, destination_type);
  CopyMetadataTo(cast_instr, new_true_value);

  auto new_false_value =
      builder.CreateCast(cast_opcode, false_value, destination_type);
  CopyMetadataTo(cast_instr, new_false_value);

  auto replacement =
      builder.CreateSelect(condition, new_true_value, new_false_value);
  CopyMetadataTo(select_instr, replacement);

  output = llvm::dyn_cast<llvm::Instruction>(replacement);
  return true;
}

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
static bool FoldSelectWithGEPInst(
    llvm::Instruction *&output, llvm::Instruction *select_instr,
    llvm::Value *condition, llvm::Value *true_value, llvm::Value *false_value,
    llvm::Instruction *gep_instr) {

  std::vector<llvm::Value *> index_list;
  if (!CollectAndValidateGEPIndexes(index_list, select_instr, gep_instr)) {
    return false;
  }

  llvm::Value *new_true_value = nullptr;
  llvm::Value *new_false_value = nullptr;
  llvm::IRBuilder<> builder(gep_instr);

  for (auto &index : index_list) {
    if (index == select_instr) {
      index = true_value;
      new_true_value = builder.CreateGEP(gep_instr->getOperand(0), index_list);
      CopyMetadataTo(gep_instr, new_true_value);
      index = false_value;
      new_false_value = builder.CreateGEP(gep_instr->getOperand(0), index_list);
      CopyMetadataTo(gep_instr, new_false_value);
      break;
    }
  }

  if (!new_true_value) {
    return false;
  }

  auto replacement =
      builder.CreateSelect(condition, new_true_value, new_false_value);
  CopyMetadataTo(select_instr, replacement);

  output = llvm::dyn_cast<llvm::Instruction>(replacement);
  return true;
}

// clang-format off
const std::unordered_map<std::uint32_t, SelectInstructionFolder> kSelectInstructionFolderMap = {

  // Binary operators
  { llvm::Instruction::Add, FoldSelectWithBinaryOp },
  { llvm::Instruction::FAdd, FoldSelectWithBinaryOp },
  { llvm::Instruction::Sub, FoldSelectWithBinaryOp },
  { llvm::Instruction::FSub, FoldSelectWithBinaryOp },
  { llvm::Instruction::Mul, FoldSelectWithBinaryOp },
  { llvm::Instruction::FMul, FoldSelectWithBinaryOp },
  { llvm::Instruction::UDiv, FoldSelectWithBinaryOp },
  { llvm::Instruction::SDiv, FoldSelectWithBinaryOp},
  { llvm::Instruction::FDiv, FoldSelectWithBinaryOp },
  { llvm::Instruction::URem, FoldSelectWithBinaryOp },
  { llvm::Instruction::SRem, FoldSelectWithBinaryOp },
  { llvm::Instruction::FRem, FoldSelectWithBinaryOp },
  { llvm::Instruction::Shl, FoldSelectWithBinaryOp },
  { llvm::Instruction::LShr, FoldSelectWithBinaryOp},
  { llvm::Instruction::AShr, FoldSelectWithBinaryOp },
  { llvm::Instruction::And, FoldSelectWithBinaryOp },
  { llvm::Instruction::Or, FoldSelectWithBinaryOp },
  { llvm::Instruction::Xor, FoldSelectWithBinaryOp },

  // Cast operators
  { llvm::Instruction::Trunc, FoldSelectWithCastInst },
  { llvm::Instruction::ZExt, FoldSelectWithCastInst },
  { llvm::Instruction::SExt, FoldSelectWithCastInst },
  { llvm::Instruction::FPToUI, FoldSelectWithCastInst },
  { llvm::Instruction::FPToSI, FoldSelectWithCastInst},
  { llvm::Instruction::UIToFP, FoldSelectWithCastInst },
  { llvm::Instruction::SIToFP,FoldSelectWithCastInst },
  { llvm::Instruction::FPTrunc, FoldSelectWithCastInst },
  { llvm::Instruction::FPExt, FoldSelectWithCastInst },
  { llvm::Instruction::PtrToInt,FoldSelectWithCastInst },
  { llvm::Instruction::IntToPtr, FoldSelectWithCastInst },
  { llvm::Instruction::BitCast, FoldSelectWithCastInst },

  // Memory operators
  { llvm::Instruction::GetElementPtr, FoldSelectWithGEPInst },
};

// clang-format on

// Case handlers for `PHINode` instructions
using PHINodeInstructionFolder =
    bool (HoistUsersOfSelectsAndPhis::PassFunctionState::*)(
        llvm::Instruction *&output, llvm::PHINode *,
        IncomingValueList &, llvm::Instruction *);

// clang-format off
const std::unordered_map<std::uint32_t, PHINodeInstructionFolder> kPHINodeFolderMap = {

  // Binary operators
  { llvm::Instruction::Add, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::FAdd, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::Sub, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::FSub, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::Mul, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::FMul, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::UDiv, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::SDiv, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::FDiv, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::URem, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::SRem, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::FRem, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::Shl, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::LShr, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::AShr, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::And, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::Or, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithBinaryOp },
  { llvm::Instruction::Xor, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithBinaryOp },

  // Cast operators
  { llvm::Instruction::Trunc, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithCastInst },
  { llvm::Instruction::ZExt, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithCastInst },
  { llvm::Instruction::SExt, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithCastInst },
  { llvm::Instruction::FPToUI, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithCastInst },
  { llvm::Instruction::FPToSI, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithCastInst },
  { llvm::Instruction::UIToFP, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithCastInst },
  { llvm::Instruction::SIToFP, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithCastInst },
  { llvm::Instruction::FPTrunc, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithCastInst },
  { llvm::Instruction::FPExt, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithCastInst },


  // NOTE(akshayk): A phi node folding with cast instructions like IntToPtr
  //                PtrToInt, and BitCast may enter into an infinite loop if
  //                the folding instruction bounce between each other. Disable
  //                them in the map and revisit when we have the fix.
  //
  // NOTE(pag): Issue manifests in ARM64 `SMIME_write_ASN1` of challenge 5.
#if 0
  { llvm::Instruction::PtrToInt, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithCastInst },
  { llvm::Instruction::IntToPtr, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithCastInst },
  { llvm::Instruction::BitCast, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithCastInst },
#endif

  // Memory operators
  { llvm::Instruction::GetElementPtr, &HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithGEPInst },
};

// clang-format on

static llvm::BasicBlock *InsertionBlock(const IncomingValue &ival) {
  if (auto incoming_inst = llvm::dyn_cast<llvm::Instruction>(ival.value)) {
    return incoming_inst->getParent();
  } else {
    return ival.basic_block;
  }
}

}  // namespace

llvm::PreservedAnalyses HoistUsersOfSelectsAndPhis::run(
    llvm::Function &function, llvm::FunctionAnalysisManager &fam) {
  if (function.isDeclaration()) {
    return llvm::PreservedAnalyses::all();
  }

  const auto &dt = fam.getResult<llvm::DominatorTreeAnalysis>(function);
  auto function_state =
      std::make_unique<HoistUsersOfSelectsAndPhis::PassFunctionState>(dt);
  // Create an initial queue of possible candidates
  auto next_worklist =
      SelectInstructions<llvm::SelectInst, llvm::PHINode>(function);

  std::unordered_set<llvm::Instruction *> visited_instructions;

  // Go through the list of discovered instructions
  InstructionList worklist;
  bool function_changed{false};
  auto num_changed = 0;

  for (auto gas = 0u; gas < 8u && !next_worklist.empty(); ++gas) {
    worklist.swap(next_worklist);
    next_worklist.clear();

    for (auto instr : worklist) {

      // Keep track of the instructions we have visited so we don't
      // loop forever
      if (visited_instructions.count(instr) != 0U) {
        continue;
      }

      visited_instructions.insert(instr);

      // Attempt to combine this instruction; the folder function also
      // drops all the instructions that are no longer needed but will
      // keep `instr` alive for now
      auto res = false;
      if (auto phi = llvm::dyn_cast<llvm::PHINode>(instr)) {
        res = function_state->FoldPHINode(next_worklist, phi);
      } else if (auto select = llvm::dyn_cast<llvm::SelectInst>(instr)) {
        res = function_state->FoldSelectInstruction(next_worklist, select);
      }

      if (res) {
        function_changed = true;
        ++num_changed;
      }
    }
  }

  // Go through the visited instructions and drop the ones we no
  // longer need. Doing the cleanup now ensures we do not risk
  // new instructions polluting the unordered_set by ending up
  // allocated at a memory location we have already seen.
  for (auto &instr : visited_instructions) {
    if (instr->use_empty()) {
      instr->eraseFromParent();
      function_changed = true;
    }
  }

  return ConvertBoolToPreserved(function_changed);
}

llvm::StringRef HoistUsersOfSelectsAndPhis::name(void) {
  return llvm::StringRef("HoistUsersOfSelectsAndPhis");
}

// If there is cyclic dependency incoming values on phi node; It can't be folded. The
// utility function checks such cases.
static bool IsPHINodeFoldable(llvm::Instruction *instr,
                              IncomingValueList &incoming_values) {
  for (auto &incoming_value : incoming_values) {
    if (llvm::isa<llvm::PHINode>(incoming_value.value)) {
      return false;
    }
    for (auto user : instr->users()) {
      if (user == incoming_value.value) {
        return false;
      }
    }
  }
  return true;
}

static llvm::PHINode *BuildPHI(
    llvm::PHINode *phi_node, llvm::Type *destination_type,
    std::map<IncomingValue, IncomingValue> new_incoming_values) {

  llvm::IRBuilder<> builder(phi_node);

  auto new_phi_node =
      builder.CreatePHI(destination_type, phi_node->getNumIncomingValues());
  CopyMetadataTo(phi_node, new_phi_node);

  // The same value may reach into the PHI node multiple times, so we need
  // to replace all cases with the same thing.
  auto incoming_value_count = phi_node->getNumIncomingValues();
  for (auto i = 0U; i < incoming_value_count; ++i) {
    IncomingValue incoming_value;
    incoming_value.value = phi_node->getIncomingValue(i);
    incoming_value.basic_block = phi_node->getIncomingBlock(i);

    auto new_incoming_value = new_incoming_values[incoming_value];
    CHECK_NOTNULL(new_incoming_value.value);
    CHECK_NOTNULL(new_incoming_value.basic_block);

    new_phi_node->addIncoming(new_incoming_value.value,
                              new_incoming_value.basic_block);
  }

  DCHECK(BasicBlockIsSane(phi_node));
  return new_phi_node;
}

bool HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithBinaryOp(
    llvm::Instruction *&output, llvm::PHINode *phi_node,
    IncomingValueList &incoming_values, llvm::Instruction *binary_op_instr) {

  // This binary operator is using our `PHINode` instruction. Take the
  // operand on the opposite side
  auto operand = binary_op_instr->getOperand(0U);
  if (operand == phi_node) {
    operand = binary_op_instr->getOperand(1U);
  }

  // In order to be able to combine these two instructions, the
  // other operand needs to be a constant
  if (!llvm::isa<llvm::Constant>(operand)) {
    return false;
  }

  // Get the binary operator opcode for later
  auto opcode =
      llvm::dyn_cast<llvm::BinaryOperator>(binary_op_instr)->getOpcode();

  // Go through each incoming value, and try to push the binary operator
  // on the other side of the PHI node
  std::map<IncomingValue, IncomingValue> new_incoming_values;

  for (IncomingValue &incoming_value : incoming_values) {

    // Set the builder inside the incoming block
    llvm::IRBuilder<> builder(InsertionBlock(incoming_value)->getTerminator());

    IncomingValue new_incoming_value;
    new_incoming_value.value =
        builder.CreateBinOp(opcode, incoming_value.value, operand);
    CopyMetadataTo(binary_op_instr, new_incoming_value.value);

    new_incoming_value.basic_block = incoming_value.basic_block;
    new_incoming_values.insert_or_assign(incoming_value,
                                         std::move(new_incoming_value));
  }

  // Move back to the current block, then rewrite the phi node
  output = BuildPHI(phi_node, phi_node->getType(),
                    std::move(new_incoming_values));
  return true;
}

bool HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithCastInst(
    llvm::Instruction *&output, llvm::PHINode *phi_node,
    IncomingValueList &incoming_values, llvm::Instruction *cast_instr) {

  llvm::Instruction::CastOps cast_opcode{};
  llvm::Type *destination_type{};

  {
    auto instr = llvm::dyn_cast<llvm::CastInst>(cast_instr);

    cast_opcode = instr->getOpcode();
    destination_type = instr->getDestTy();
  }

  // Go through each incoming value, and try to push the cast operator
  // on the other side of the PHI node
  std::map<IncomingValue, IncomingValue> new_incoming_values;

  for (auto &incoming_value : incoming_values) {

    // Set the builder inside the incoming block
    llvm::IRBuilder<> builder(InsertionBlock(incoming_value)->getTerminator());

    IncomingValue new_incoming_value;
    new_incoming_value.value =
        builder.CreateCast(cast_opcode, incoming_value.value, destination_type);
    CopyMetadataTo(cast_instr, new_incoming_value.value);

    new_incoming_value.basic_block = incoming_value.basic_block;
    new_incoming_values.insert_or_assign(incoming_value,
                                         std::move(new_incoming_value));
  }

  output = BuildPHI(phi_node, destination_type, std::move(new_incoming_values));
  return true;
}

bool HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINodeWithGEPInst(
    llvm::Instruction *&output, llvm::PHINode *phi_node,
    IncomingValueList &incoming_values, llvm::Instruction *gep_instr) {

  std::vector<llvm::Value *> index_list;
  if (!CollectAndValidateGEPIndexes(index_list, phi_node, gep_instr)) {
    return false;
  }

  // If the GEP instruction is in a different block than the PHI node then
  // we can't replace the GEP with a PHI of a bunch of GEPs because then
  // we can't prove that this new PHI dominates all uses of the GEP.
  llvm::BasicBlock *const curr_block = phi_node->getParent();
  if (gep_instr->getParent() != curr_block) {
    return false;
  }

  const auto base_ptr = gep_instr->getOperand(0);

  std::unordered_map<llvm::Value *,
                     std::unordered_map<llvm::BasicBlock *, llvm::Value *>>
      value_map;

  for (llvm::Use &op : gep_instr->operands()) {
    auto v = op.get();
    auto cv = llvm::dyn_cast<llvm::Constant>(v);
    auto av = llvm::dyn_cast<llvm::Argument>(v);

    // Map the constants/arguments as being available in all predecessor blocks.
    if (cv || av) {
      auto &vals = value_map[v];
      for (auto &incoming_val : incoming_values) {
        vals[incoming_val.basic_block] = v;
      }
      continue;
    }

    // Check the dominator tree.
    if (auto iv = llvm::dyn_cast<llvm::Instruction>(v)) {
      if (iv->getParent() == curr_block) {
        continue;  // Don't bother checking.
      }

      auto all_dominated = true;
      for (auto &incoming_val : incoming_values) {
        if (!dt.dominates(iv, incoming_val.basic_block->getTerminator())) {
          all_dominated = false;
          break;
        }
      }

      // If the base pointer/index of this GEP dominates all terminators of
      // the incoming blocks of this PHI, then we can safely use the value in
      // all predecessor blocks just before the terminator.
      if (all_dominated) {
        auto &vals = value_map[v];
        for (auto &incoming_val : incoming_values) {
          vals[incoming_val.basic_block] = v;
        }
      }
    }
  }

  // The dominator tree analysis above will fail for PHI nodes in this block.
  // It's possible that a GEP node is of the form:
  //
  //      %base = phi [base1, pred1], [base2, pred2]
  //      %index = phi [index1, pred1], [index2, pred2]
  //      %gep = gep %base, 0, %index
  //
  // In this case, we want our value map to discover that `index` has a mapped
  // value for each predecessor block, specifically, `index1` and `index2`.
  for (auto &inst : *curr_block) {
    if (auto phi_in_block = llvm::dyn_cast<llvm::PHINode>(&inst)) {
      auto &vals = value_map[phi_in_block];
      auto num_incoming_blocks = phi_in_block->getNumIncomingValues();
      for (auto i = 0u; i < num_incoming_blocks; ++i) {
        auto iv = phi_in_block->getIncomingValue(i);
        auto ib = phi_in_block->getIncomingBlock(i);
        vals[ib] = iv;
      }
    } else {
      break;
    }
  }

  // Now check that we can hoist this GEP out. This requires that we have
  // something in the value map for all operands of the GEP.
  for (llvm::Use &op : gep_instr->operands()) {
    llvm::Value *const v = op.get();
    if (value_map.find(v) == value_map.end()) {
      return false;
    }
  }

  // Go through each incoming value and move the `GetElementPtrInst`
  // instruction on each incoming basic block
  std::map<IncomingValue, IncomingValue> new_incoming_values;

  std::vector<llvm::Value *> mapped_index_list;
  mapped_index_list.reserve(index_list.size());

  for (auto &incoming_value : incoming_values) {

    // Apply the value map to the index list.
    mapped_index_list.clear();
    for (auto iv : index_list) {
      mapped_index_list.push_back(value_map[iv][incoming_value.basic_block]);
    }

    // Set the builder inside the incoming block
    llvm::IRBuilder<> builder(InsertionBlock(incoming_value)->getTerminator());

    IncomingValue new_incoming_value;
    new_incoming_value.basic_block = incoming_value.basic_block;
    new_incoming_value.value = builder.CreateGEP(
        value_map[base_ptr][incoming_value.basic_block], mapped_index_list);
    CopyMetadataTo(gep_instr, new_incoming_value.value);

    new_incoming_values.insert_or_assign(
        incoming_value, std::move(new_incoming_value));
  }

  // Move back to the current block, then rewrite the phi node; on this
  // side, we have to use the type returned by the GEP instruction

  output = BuildPHI(phi_node, gep_instr->getType(),
                    std::move(new_incoming_values));
  return true;
}

bool HoistUsersOfSelectsAndPhis::PassFunctionState::FoldPHINode(
    HoistUsersOfSelectsAndPhis::InstructionList &output,
    llvm::PHINode *instr) {

  // Extract the incoming values
  IncomingValueList incoming_value_list;

  // FoldPHINode is automatically called for PHINode types
  // (see kInstructionFolderMap)
  auto incoming_value_count = instr->getNumIncomingValues();
  for (auto i = 0U; i < incoming_value_count; ++i) {
    IncomingValue incoming_value;
    incoming_value.value = instr->getIncomingValue(i);
    incoming_value.basic_block = instr->getIncomingBlock(i);
    incoming_value_list.emplace_back(std::move(incoming_value));
  }

  // The same value may reach into the PHI node multiple times, so we need
  // to replace all cases with the same thing.
  std::sort(incoming_value_list.begin(), incoming_value_list.end());
  auto it = std::unique(incoming_value_list.begin(), incoming_value_list.end());
  incoming_value_list.erase(it, incoming_value_list.end());

  if (!IsPHINodeFoldable(instr, incoming_value_list)) {
    return false;
  }

  // Postpone the replacement and cleanup at the end of the
  // rewrite to avoid possible issues with PHI nodes or
  // iterator invalidation
  InstructionReplacementList inst_replacement_list;

  // Go through all the users of this `phi` instruction
  for (auto user : instr->users()) {
    InstructionReplacement repl;
    repl.original_instr = llvm::dyn_cast<llvm::Instruction>(user);

    // Search for a function that knows how to handle this case
    auto instr_folder_it =
        kPHINodeFolderMap.find(repl.original_instr->getOpcode());
    if (instr_folder_it == kPHINodeFolderMap.end()) {
      continue;
    }

    const auto instr_folder = instr_folder_it->second;
    if (!(this->*instr_folder)(repl.replacement_instr, instr,
                               incoming_value_list, repl.original_instr)) {
      continue;
    }

    output.push_back(repl.replacement_instr);
    inst_replacement_list.push_back(std::move(repl));
  }

  // Finally, drop all the instructions we no longer need; the `PHINode`
  // instruction will be deleted later by the caller
  auto function_changed = !inst_replacement_list.empty();
  PerformInstructionReplacements(inst_replacement_list);

  for (IncomingValue &incoming_value : incoming_value_list) {
    auto value_as_instr =
        llvm::dyn_cast<llvm::Instruction>(incoming_value.value);

    if (value_as_instr == nullptr) {
      continue;
    }

    if (value_as_instr->use_empty()) {
      value_as_instr->eraseFromParent();
    }
  }

  return function_changed;
}

bool HoistUsersOfSelectsAndPhis::PassFunctionState::FoldSelectInstruction(
    HoistUsersOfSelectsAndPhis::InstructionList &output,
    llvm::SelectInst *instr) {

  // Extract the condition and the two operands for later
  llvm::Value *condition{instr->getCondition()};
  llvm::Value *true_value{instr->getTrueValue()};
  llvm::Value *false_value{instr->getFalseValue()};


  // Postpone the replacement and cleanup at the end of the
  // rewrite to avoid possible issues with PHI nodes or
  // iterator invalidation
  InstructionReplacementList inst_replacement_list;

  // Go through all the users of this `select` instruction
  for (llvm::User *user : instr->users()) {
    InstructionReplacement repl;
    repl.original_instr = llvm::dyn_cast<llvm::Instruction>(user);

    // Search for a function that knows how to handle this case
    auto instr_folder_it =
        kSelectInstructionFolderMap.find(repl.original_instr->getOpcode());

    if (instr_folder_it == kSelectInstructionFolderMap.end()) {
      continue;
    }

    const auto &instr_folder = instr_folder_it->second;
    if (!instr_folder(repl.replacement_instr, instr, condition, true_value,
                      false_value, repl.original_instr)) {
      continue;
    }

    output.push_back(repl.replacement_instr);
    inst_replacement_list.push_back(std::move(repl));
  }

  // Finally, drop all the instructions we no longer need; the `SelectInst`
  // instruction will be deleted later by the caller
  auto function_changed = !inst_replacement_list.empty();
  PerformInstructionReplacements(inst_replacement_list);

  return function_changed;
}

void AddHoistUsersOfSelectsAndPhis(llvm::FunctionPassManager &fpm) {
  fpm.addPass(HoistUsersOfSelectsAndPhis());
}

}  // namespace anvill
