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
#include <magic_enum.hpp>

#include "Utils.h"

namespace anvill {
RecoverStackFrameInformation *
RecoverStackFrameInformation::Create(ITransformationErrorManager &error_manager,
                                     const LifterOptions &options) {
  return new RecoverStackFrameInformation(error_manager, options);
}

bool RecoverStackFrameInformation::Run(llvm::Function &function) {
  if (function.isDeclaration()) {
    return false;
  }

  // Analyze the stack frame first, enumerating the load/store instructions
  // and determining the boundaries of the stack memory
  auto module = function.getParent();
  auto original_ir = GetModuleIR(*module);

  auto stack_frame_analysis_res = AnalyzeStackFrame(function);
  if (!stack_frame_analysis_res.Succeeded()) {
    EmitError(SeverityType::Error, stack_frame_analysis_res.Error(),
              "The stack frame analysis has failed");

    return false;
  }

  auto stack_frame_analysis = stack_frame_analysis_res.TakeValue();
  if (stack_frame_analysis.size == 0) {
    return false;
  }

  // It is now time to patch the function. This method will take the stack
  // analysis and use it to generate a stack frame type and update all the
  // store and load instructions
  auto update_func_res = UpdateFunction(
      function, stack_frame_analysis, options.stack_frame_struct_init_procedure,
      options.stack_frame_lower_padding, options.stack_frame_higher_padding);

  if (!update_func_res.Succeeded()) {
    EmitError(
        SeverityType::Fatal, update_func_res.Error(),
        "Function transformation has failed and the stack could not be recovered");

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
  if (function.isDeclaration()) {
    return StackAnalysisErrorCode::InvalidParameter;
  }

  StackPointerRegisterUsages output;

  // Enumerate all the instructions we have, looking for `store` and
  // `load` instructions that reference the stack pointer
  auto module = function.getParent();
  auto data_layout = module->getDataLayout();

  for (auto &basic_block : function) {
    for (auto &instr : basic_block) {
      if (!IsMemoryOperation(instr)) {
        continue;
      }

      if (InstructionReferencesStackPointer(data_layout, instr)) {
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
    // Get the operands
    const llvm::Value *pointer_operand{nullptr};
    llvm::Type *operand_type{nullptr};

    if (auto load_inst = llvm::dyn_cast<llvm::LoadInst>(stack_ptr_usage);
        load_inst != nullptr) {
      pointer_operand = load_inst->getPointerOperand();
      operand_type = load_inst->getType();

    } else if (auto store_inst =
                   llvm::dyn_cast<llvm::StoreInst>(stack_ptr_usage);
               store_inst != nullptr) {
      auto value_operand = store_inst->getValueOperand();
      operand_type = value_operand->getType();

      pointer_operand = store_inst->getPointerOperand();

    } else {
      // This instruction is using __anvill_sp but it's not a memory read
      // or write operation
      continue;
    }

    // We may have found this instruction only because the value operand
    // references the special `__anvill_sp` symbol. If that's the case, then
    // it can be safely ignored
    if (!IsRelatedToStackPointer(data_layout,
                                 const_cast<llvm::Value *>(pointer_operand))) {
      continue;
    }

    // Resolve to a displacement
    auto resolved_stack_ptr = resolver.TryResolveReference(
        const_cast<llvm::Value *>(pointer_operand));

    if (!resolved_stack_ptr.is_valid) {
      return StackAnalysisErrorCode::StackPointerResolutionError;
    }

    if (!resolved_stack_ptr.references_stack_pointer) {
      // We already know it's related to a stack pointer, so if we fail
      // this error happened inside our helpers
      return StackAnalysisErrorCode::InternalError;
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
    StackFrameAnalysis::StackOperation stack_operation = {};
    stack_operation.instr = stack_ptr_usage;
    stack_operation.offset = displacement;
    stack_operation.type = operand_type;

    output.stack_operation_list.push_back(std::move(stack_operation));
  }

  auto stack_frame_size = output.highest_offset - output.lowest_offset;

  output.size = static_cast<std::size_t>(stack_frame_size);
  return output;
}

Result<llvm::StructType *, StackAnalysisErrorCode>
RecoverStackFrameInformation::GenerateStackFrameType(
    const llvm::Function &function,
    const StackFrameAnalysis &stack_frame_analysis, std::size_t padding_bytes) {
  if (stack_frame_analysis.size == 0) {
    return StackAnalysisErrorCode::InvalidParameter;
  }

  // Generate a stack frame type with a name that matches the
  // anvill ABI
  auto function_name = function.getName().str();
  auto stack_frame_type_name = function_name + kStackFrameTypeNameSuffix;

  // Make sure this type is not defined already
  auto &module = *function.getParent();
  auto stack_frame_type = module.getTypeByName(stack_frame_type_name);
  if (stack_frame_type != nullptr) {
    return StackAnalysisErrorCode::StackFrameTypeAlreadyExists;
  }

  // Determine how many bytes we should allocate. We may have been
  // asked to add some additional padding. We don't care how it is
  // accessed right now, we just add them to the total size
  auto stack_frame_size = padding_bytes + stack_frame_analysis.size;

  // Generate the stack frame using a byte array
  auto &context = module.getContext();

  auto array_elem_type = llvm::Type::getInt8Ty(context);
  auto byte_array_type =
      llvm::ArrayType::get(array_elem_type, stack_frame_size);

  const std::vector<llvm::Type *> stack_frame_types = {byte_array_type};
  stack_frame_type =
      llvm::StructType::create(stack_frame_types, stack_frame_type_name, true);

  if (stack_frame_type == nullptr) {
    return StackAnalysisErrorCode::InternalError;
  }

  return stack_frame_type;
}

Result<llvm::GlobalVariable *, StackAnalysisErrorCode>
RecoverStackFrameInformation::GetStackSymbolicByteValue(llvm::Module &module,
                                                        std::int32_t offset) {
  // Create a new name
  auto value_name = kSymbolicStackFrameValuePrefix;
  if (offset < 0) {
    value_name += "minus_";
  } else if (offset > 0) {
    value_name += "plus_";
  }

  value_name += std::to_string(abs(offset));

  // Get the symbolic value; this will fail if we already have
  // one with the same name but wrong type
  auto &context = module.getContext();
  auto byte_type = llvm::Type::getInt8Ty(context);

  auto symbolic_value_res = GetSymbolicValue(module, byte_type, value_name);
  if (!symbolic_value_res.Succeeded()) {
    return StackAnalysisErrorCode::StackInitializationError;
  }

  return symbolic_value_res.TakeValue();
}

Result<std::monostate, StackAnalysisErrorCode>
RecoverStackFrameInformation::UpdateFunction(
    llvm::Function &function, const StackFrameAnalysis &stack_frame_analysis,
    StackFrameStructureInitializationProcedure init_strategy,
    std::size_t stack_frame_lower_padding,
    std::size_t stack_frame_higher_padding) {

  if (function.isDeclaration() || stack_frame_analysis.size == 0U) {
    return StackAnalysisErrorCode::InvalidParameter;
  }

  // Generate a new stack frame type, using a byte array inside a
  // StructType
  auto padding_bytes = stack_frame_lower_padding + stack_frame_higher_padding;

  auto stack_frame_type_res =
      GenerateStackFrameType(function, stack_frame_analysis, padding_bytes);

  if (!stack_frame_type_res.Succeeded()) {
    return stack_frame_type_res.TakeError();
  }

  auto stack_frame_type = stack_frame_type_res.TakeValue();

  // Take the first instruction as an insert pointer for the
  // IRBuilder, and then create an `alloca` instruction to
  // generate our new stack frame
  auto &entry_block = function.getEntryBlock();
  auto &insert_point = *entry_block.getFirstInsertionPt();

  llvm::IRBuilder<> builder(&insert_point);
  auto stack_frame_alloca = builder.CreateAlloca(stack_frame_type);

  // When we have padding enabled in the configuration, we must
  // make sure that accesses are still correctly centered around the
  // stack pointer we were given (i.e.: we don't alter where the
  // `__anvill_stack_0` is supposed to land).
  //
  // This is true regardless of which initialization method we use, but
  // the following example assumes kSymbolic since it makes the
  // explanation easier to follow.
  //
  //     [higher addresses]
  //
  //     [__anvill_stack_plus_3    <- optional higher padding]
  //
  //     __anvill_stack_plus_2
  //     __anvill_stack_plus_1
  //     __anvill_stack_0          <- __anvill_sp
  //     __anvill_stack_minus_1
  //     __anvill_stack_minus_2
  //
  //     [__anvill_stack_minus_3   <- optional lower padding]
  //
  //     [lower addresses]

  auto base_stack_offset = stack_frame_analysis.lowest_offset -
                           static_cast<std::int32_t>(stack_frame_lower_padding);

  auto total_stack_frame_size = padding_bytes + stack_frame_analysis.size;

  // Pre-initialize the stack frame if we have been requested to do so. This
  // covers the frame padding bytes as well.
  //
  // Look at the definition for the `StackFrameStructureInitializationProcedure`
  // enum class to get more details on each initialization strategy.
  switch (init_strategy) {
    case StackFrameStructureInitializationProcedure::kZeroes: {
      // Initialize to zero
      auto null_value = llvm::Constant::getNullValue(stack_frame_type);
      builder.CreateStore(null_value, stack_frame_alloca);
      break;
    }

    case StackFrameStructureInitializationProcedure::kUndef: {
      // Mark the stack values as explicitly undefined
      auto undef_value = llvm::UndefValue::get(stack_frame_type);
      builder.CreateStore(undef_value, stack_frame_alloca);
      break;
    }

    case StackFrameStructureInitializationProcedure::kSymbolic: {
      // Generate symbolic values for each byte in the stack frame
      auto &module = *function.getParent();

      auto current_offset = base_stack_offset;

      llvm::Value *gep_indexes[] = {builder.getInt32(0), builder.getInt32(0),
                                    nullptr};

      for (auto i = 0U; i < total_stack_frame_size; ++i) {
        gep_indexes[2] = builder.getInt32(i);
        auto stack_frame_byte =
            builder.CreateGEP(stack_frame_alloca, gep_indexes);

        auto symbolic_value_ptr_res =
            GetStackSymbolicByteValue(module, current_offset);

        if (!symbolic_value_ptr_res.Succeeded()) {
          return symbolic_value_ptr_res.TakeError();
        }

        auto symbolic_value_ptr = symbolic_value_ptr_res.TakeValue();
        ++current_offset;

        auto symbolic_value = builder.CreateLoad(symbolic_value_ptr);
        builder.CreateStore(symbolic_value, stack_frame_byte);
      }

      break;
    }

    case StackFrameStructureInitializationProcedure::kNone: {
      // Skip initialization
      break;
    }
  }

  // The stack analysis we have performed earlier contains all the
  // `load` and `store` instructions that we have to update
  for (auto &stack_operation : stack_frame_analysis.stack_operation_list) {
    // Convert the `__anvill_sp`-relative offset to a 0-based index
    // into our stack frame type
    auto displacement =
        stack_operation.offset - stack_frame_analysis.lowest_offset;

    // If we added padding, adjust the displacement value. We just have
    // to add the amount of bytes we have inserted before the stack pointer
    displacement += stack_frame_lower_padding;

    // Create a GEP instruction that accesses the new stack frame we
    // created based on the relative offset
    //
    // As a reminder, the stack frame type is a StructType that contains
    // an ArrayType with int8 elements
    builder.SetInsertPoint(stack_operation.instr);

    auto stack_frame_ptr = builder.CreateGEP(
        stack_frame_alloca, {builder.getInt32(0), builder.getInt32(0),
                             builder.getInt32(displacement)});

    stack_frame_ptr = builder.CreateBitCast(
        stack_frame_ptr, stack_operation.type->getPointerTo());

    // Replace the original `load` or `store` instruction with a matching
    // instruction that operates on the allocated stack frame type instead
    llvm::Value *replacement{nullptr};

    if (auto load_inst = llvm::dyn_cast<llvm::LoadInst>(stack_operation.instr);
        load_inst != nullptr) {

      replacement = builder.CreateLoad(stack_frame_ptr);

    } else if (auto store_inst =
                   llvm::dyn_cast<llvm::StoreInst>(stack_operation.instr);
               store_inst != nullptr) {

      auto value_operand = store_inst->getValueOperand();
      replacement = builder.CreateStore(value_operand, stack_frame_ptr);

    } else {
      return StackAnalysisErrorCode::UnsupportedInstruction;
    }

    stack_operation.instr->replaceAllUsesWith(replacement);
    stack_operation.instr->eraseFromParent();
  }

  return std::monostate();
}

RecoverStackFrameInformation::RecoverStackFrameInformation(
    ITransformationErrorManager &error_manager, const LifterOptions &options)
    : BaseFunctionPass(error_manager),
      options(options) {}

llvm::FunctionPass *
CreateRecoverStackFrameInformation(ITransformationErrorManager &error_manager,
                                   const LifterOptions &options) {
  return RecoverStackFrameInformation::Create(error_manager, options);
}

}  // namespace anvill
