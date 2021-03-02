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

#include "RecoverStackFrameInformation.h"

#include <anvill/ABI.h>
#include <anvill/Analysis/CrossReferenceResolver.h>
#include <anvill/Analysis/Utils.h>
#include <glog/logging.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>

#include <limits>

namespace anvill {

RecoverStackFrameInformation *RecoverStackFrameInformation::Create(void) {
  return new RecoverStackFrameInformation();
}

bool RecoverStackFrameInformation::runOnFunction(llvm::Function &function) {
  if (function.empty()) {
    return false;
  }

  // Analyze the stack frame first, enumerating the load/store instructions
  // and determining the boundaries of the stack memory
  auto stack_frame_analysis_res = AnalyzeStackFrame(function);
  if (!stack_frame_analysis_res.Succeeded()) {
    auto &error_code = stack_frame_analysis_res.Error();
    LOG(FATAL) << "Stack frame analysis failed: " << std::hex
               << static_cast<int>(error_code);

    return false;
  }

  auto stack_frame_analysis = stack_frame_analysis_res.TakeValue();
  if (stack_frame_analysis.size == 0) {
    return false;
  }

  // It is now time to patch the function. This method will take the stack
  // analysis and use it to generate a stack frame type and update all the
  // store and load instructions
  auto update_func_res = UpdateFunction(function, stack_frame_analysis);
  if (!update_func_res.Succeeded()) {
    auto &error_code = stack_frame_analysis_res.Error();
    LOG(FATAL) << "Function transformation has failed: " << std::hex
               << static_cast<int>(error_code);

    return false;
  }

  return true;
}

llvm::StringRef RecoverStackFrameInformation::getPassName(void) const {
  return llvm::StringRef("RecoverStackFrameInformation");
}

Result<StackPointerRegisterUsages, StackAnalysisErrorCode>
RecoverStackFrameInformation::EnumerateStackPointerUsages(
    llvm::Function &function) {
  if (function.empty()) {
    return StackAnalysisErrorCode::InvalidParameter;
  }

  StackPointerRegisterUsages output;

  // Enumerate all the instructions we have, looking for `store` and
  // `load` instructions that reference the stack pointer
  for (auto &basic_block : function) {
    for (auto &instr : basic_block) {
      if (!IsMemoryOperation(instr)) {
        continue;
      }

      if (InstructionReferencesStackPointer(instr)) {
        output.push_back(&instr);
      }
    }
  }

  return output;
}

Result<StackFrameAnalysis, StackAnalysisErrorCode>
RecoverStackFrameInformation::AnalyzeStackFrame(llvm::Function &function) {
  // Enumerate all the `store` and `load` instructions operating on
  // the stack pointer
  auto stack_ptr_usages_res = EnumerateStackPointerUsages(function);
  if (!stack_ptr_usages_res.Succeeded()) {
    return stack_ptr_usages_res.TakeError();
  }

  // Go through each instruction, and attempt to determine
  // what are the stack boundaries
  auto module = function.getParent();
  auto data_layout = module->getDataLayout();

  CrossReferenceResolver resolver(data_layout);

  StackFrameAnalysis output;
  output.highest_offset = std::numeric_limits<std::int32_t>::min();
  output.lowest_offset = std::numeric_limits<std::int32_t>::max();

  auto stack_ptr_usages = stack_ptr_usages_res.TakeValue();
  for (const auto &stack_ptr_usage : stack_ptr_usages) {
    // Get the memory operands
    const llvm::Value *stack_pointer{nullptr};
    llvm::Type *operand_type{nullptr};

    if (auto load_inst = llvm::dyn_cast<llvm::LoadInst>(stack_ptr_usage);
        load_inst != nullptr) {
      stack_pointer = load_inst->getPointerOperand();
      operand_type = load_inst->getType();

    } else if (auto store_inst =
                   llvm::dyn_cast<llvm::StoreInst>(stack_ptr_usage);
               store_inst != nullptr) {
      auto value_operand = store_inst->getValueOperand();
      operand_type = value_operand->getType();

      stack_pointer = store_inst->getPointerOperand();

    } else {
      return StackAnalysisErrorCode::UnsupportedInstruction;
    }

    // Resolve to a displacement
    auto resolved_stack_ptr =
        resolver.TryResolveReference(const_cast<llvm::Value *>(stack_pointer));

    if (!resolved_stack_ptr.is_valid ||
        !resolved_stack_ptr.references_stack_pointer) {
      return StackAnalysisErrorCode::StackPointerResolutionError;
    }

    auto displacement =
        static_cast<std::int32_t>(resolved_stack_ptr.u.displacement);

    auto operand_size =
        static_cast<std::int32_t>(data_layout.getTypeAllocSize(operand_type));

    // Update the boundaries
    output.highest_offset =
        std::max(output.highest_offset, displacement + operand_size);

    output.lowest_offset = std::min(output.lowest_offset, displacement);

    // Save the instruction pointer and the memory information
    StackFrameAnalysis::MemoryInformation memory_info = {};
    memory_info.offset = displacement;
    memory_info.type = operand_type;

    output.instruction_map.insert({stack_ptr_usage, memory_info});
  }

  auto stack_frame_size = output.highest_offset - output.lowest_offset;

  output.size = static_cast<std::size_t>(stack_frame_size);
  return output;
}

Result<llvm::StructType *, StackAnalysisErrorCode>
RecoverStackFrameInformation::GenerateStackFrameType(
    const llvm::Function &function,
    const StackFrameAnalysis &stack_frame_analysis) {
  if (stack_frame_analysis.size == 0) {
    return StackAnalysisErrorCode::InvalidParameter;
  }

  auto function_name = function.getName().str();
  auto stack_frame_type_name = function_name + kStackFrameTypeNameSuffix;

  auto &module = *function.getParent();
  auto stack_frame_type = module.getTypeByName(stack_frame_type_name);
  if (stack_frame_type != nullptr) {
    return StackAnalysisErrorCode::StackFrameTypeAlreadyExists;
  }

  auto &context = module.getContext();

  auto array_elem_type = llvm::Type::getInt8Ty(context);
  auto byte_array_type =
      llvm::ArrayType::get(array_elem_type, stack_frame_analysis.size);

  const std::vector<llvm::Type *> stack_frame_types = {byte_array_type};
  stack_frame_type =
      llvm::StructType::create(stack_frame_types, stack_frame_type_name, true);

  if (stack_frame_type == nullptr) {
    return StackAnalysisErrorCode::InternalError;
  }

  return stack_frame_type;
}

Result<std::monostate, StackAnalysisErrorCode>
RecoverStackFrameInformation::UpdateFunction(
    llvm::Function &function, const StackFrameAnalysis &stack_frame_analysis) {

  if (function.empty() || stack_frame_analysis.size == 0U) {
    return StackAnalysisErrorCode::InvalidParameter;
  }

  // Generate a new stack frame type, using a byte array inside a
  // StructType
  auto stack_frame_type_res =
      GenerateStackFrameType(function, stack_frame_analysis);

  if (!stack_frame_type_res.Succeeded()) {
    return stack_frame_type_res.TakeError();
  }

  auto stack_frame_type = stack_frame_type_res.TakeValue();

  // Take the first instruction as an insert pointer for the
  // IRBuilder, and then create an `alloca` instruction to
  // generate our new stack frame
  auto &entry_block = function.getEntryBlock();

  auto first_instr_it = entry_block.begin();
  if (first_instr_it == entry_block.end()) {
    return StackAnalysisErrorCode::InternalError;
  }

  auto first_instr = &(*first_instr_it);

  llvm::IRBuilder<> builder(first_instr);
  auto stack_frame_alloca = builder.CreateAlloca(stack_frame_type);

  // The stack analysis we have performed earlier contains all the
  // `load` and `store` instructions that we have to update
  for (auto &p : stack_frame_analysis.instruction_map) {
    auto &instr = p.first;
    auto &memory_info = p.second;

    // Convert the __anvill_sp-relative offset to a 0-based index
    // into our stack frame type
    auto displacement = memory_info.offset - stack_frame_analysis.lowest_offset;

    // Create a GEP instruction that accesses the new stack frame we
    // created based on the relative offset
    //
    // As a reminder, the stack frame type is a StructType that contains
    // an ArrayType with int8 elements
    builder.SetInsertPoint(instr);

    auto stack_frame_ptr = builder.CreateGEP(
        stack_frame_alloca, {builder.getInt32(0), builder.getInt32(0),
                             builder.getInt32(displacement)});

    stack_frame_ptr = builder.CreateBitCast(stack_frame_ptr,
                                            memory_info.type->getPointerTo());

    // Replace the original `load` or `store` instruction with a matching
    // instruction that operates on the allocated stack frame type instead
    llvm::Value *replacement{nullptr};

    if (auto load_inst = llvm::dyn_cast<llvm::LoadInst>(instr);
        load_inst != nullptr) {

      replacement = builder.CreateLoad(stack_frame_ptr);

    } else if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(instr);
               store_inst != nullptr) {

      auto value_operand = store_inst->getValueOperand();
      replacement = builder.CreateStore(value_operand, stack_frame_ptr);

    } else {
      return StackAnalysisErrorCode::UnsupportedInstruction;
    }

    instr->replaceAllUsesWith(replacement);
    instr->eraseFromParent();
  }

  return std::monostate();
}

llvm::FunctionPass *CreateRecoverStackFrameInformation(void) {
  return RecoverStackFrameInformation::Create();
}

}  // namespace anvill
