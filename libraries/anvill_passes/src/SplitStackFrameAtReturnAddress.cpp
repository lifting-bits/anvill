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

#include "SplitStackFrameAtReturnAddress.h"

#include <anvill/ABI.h>
#include <anvill/Transforms.h>
#include <glog/logging.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>
#include <remill/BC/Util.h>

#include <magic_enum.hpp>

#include "Utils.h"

namespace anvill {
SplitStackFrameAtReturnAddress *SplitStackFrameAtReturnAddress::Create(
    ITransformationErrorManager &error_manager) {
  static_cast<void>(error_manager);
  return new SplitStackFrameAtReturnAddress(error_manager);
}

bool SplitStackFrameAtReturnAddress::Run(llvm::Function &function) {
  if (function.empty()) {
    return false;
  }

  auto module = function.getParent();
  auto original_ir = GetModuleIR(*module);

  // Check whether the stack frame structure should be considered for
  // patching
  auto stack_frame_type_res = GetFunctionStackFrameType(function);
  if (!stack_frame_type_res.Succeeded()) {
    return false;
  }

  auto stack_frame_type = stack_frame_type_res.TakeValue();
  if (stack_frame_type->getNumElements() <= 1U) {

    // Not an error, the stack frame struct exists but it's either
    // empty or populated with a single element
    return false;
  }

  // Enumerate the store instructions that identify a stack frame
  // that we need to split
  auto retn_addr_store_instr_res = GetRetnAddressStoreInstructions(function);
  if (!retn_addr_store_instr_res.Succeeded()) {
    auto error_code = retn_addr_store_instr_res.TakeError();
    if (error_code == StackFrameSplitErrorCode::StackFrameAllocationNotFound) {
      return false;
    }

    auto error_name = std::string(magic_enum::enum_name(error_code));
    EmitError(SeverityType::Error, error_name,
              "Failed to identify which instructions access the stack frame");

    return false;
  }

  auto retn_addr_store_instr = retn_addr_store_instr_res.TakeValue();
  if (retn_addr_store_instr.store_off_pairs.empty()) {
    // No error, the function does not need patching
    return false;
  }

  if (retn_addr_store_instr.store_off_pairs.size() > 1) {
    // We only handle the first instance, so return an error if
    // we have more
    auto error_code = StackFrameSplitErrorCode::NotSupported;
    auto error_name = std::string(magic_enum::enum_name(error_code));

    EmitError(
        SeverityType::Error, error_name,
        "There are too many instructios writing the retn address. Aborting");

    return false;
  }

  const auto &store_off = retn_addr_store_instr.store_off_pairs.front();
  auto retn_addr_offset = std::get<1>(store_off);

  auto split_res = SplitStackFrameAtOffset(function, retn_addr_offset,
                                           retn_addr_store_instr.alloca_inst);

  if (!split_res.Succeeded()) {
    auto error_code = split_res.TakeError();
    auto error_name = std::string(magic_enum::enum_name(error_code));

    auto transformed_ir = GetModuleIR(*module);

    EmitError(SeverityType::Fatal, error_name,
              "Failed to transform the function");

    return false;
  }

  return true;
}

Result<std::vector<llvm::StructType *>, StackFrameSplitErrorCode>
SplitStackFrameAtReturnAddress::SplitStackFrameTypeAtOffset(
    const llvm::Function &function, std::int64_t offset,
    const llvm::StructType *stack_frame_type) {

  std::vector<llvm::StructType *> output;

  auto module = function.getParent();

  auto elem_count = stack_frame_type->getNumElements();
  if (elem_count <= 1U) {

    // When we only have one element in the stack, there's nothing
    // we have to patch
    return output;
  }

  auto elem_index_res =
      StructOffsetToElementIndex(module, stack_frame_type, offset);

  if (!elem_index_res.Succeeded()) {
    return elem_index_res.TakeError();
  }

  auto elem_index = elem_index_res.TakeValue();

  // There are three different outcomes, depending on where the
  // element we have to isolate lives:
  //
  // 1. First element
  //    struct_definition_list[0] is left empty
  //    struct_definition_list[1] the retn address
  //    struct_definition_list[2] contains everything else
  //
  // 2. Middle element
  //    struct_definition_list[0] everything at the left of the retn address
  //    struct_definition_list[1] the retn address
  //    struct_definition_list[2] everything at the right of the retn address
  //
  // 3. Last element
  //    struct_definition_list[0] everything at the left of the retn address
  //    struct_definition_list[1] the retn address
  //    struct_definition_list[2] is left empty

  using StructDefinition = std::vector<llvm::Type *>;
  std::array<StructDefinition, 3> struct_definition_list;

  for (auto i = 0U; i < elem_count; ++i) {
    auto elem_type = stack_frame_type->getElementType(i);

    if (i < elem_index) {
      struct_definition_list[0].push_back(elem_type);

    } else if (i == elem_index) {
      struct_definition_list[1].push_back(elem_type);

    } else {
      struct_definition_list[2].push_back(elem_type);
    }
  }

  auto base_stack_frame_type_name = GetFunctionStackFrameTypeName(function);

  auto &context = module->getContext();

  std::size_t part_name{};
  for (const auto &struct_definition : struct_definition_list) {
    if (struct_definition.empty()) {
      continue;
    }

    auto struct_name =
        base_stack_frame_type_name + "_part" + std::to_string(part_name);

    auto stack_frame_part =
        llvm::StructType::create(context, struct_definition, struct_name);

    output.push_back(stack_frame_part);

    ++part_name;
  }

  return output;
}

llvm::StringRef SplitStackFrameAtReturnAddress::getPassName(void) const {
  return llvm::StringRef("SplitStackFrameAtReturnAddress");
}

std::string SplitStackFrameAtReturnAddress::GetFunctionStackFrameTypeName(
    const llvm::Function &function) {
  return function.getName().str() + kStackFrameTypeNameSuffix;
}

Result<const llvm::StructType *, StackFrameSplitErrorCode>
SplitStackFrameAtReturnAddress::GetFunctionStackFrameType(
    const llvm::Function &function) {

  auto module = function.getParent();

  auto type = module->getTypeByName(GetFunctionStackFrameTypeName(function));
  if (type == nullptr) {
    return StackFrameSplitErrorCode::MissingFunctionStackFrameType;
  }

  return type;
}

Result<llvm::AllocaInst *, StackFrameSplitErrorCode>
SplitStackFrameAtReturnAddress::GetStackFrameAllocaInst(
    llvm::Function &valid_func) {

  auto expected_type_name = GetFunctionStackFrameTypeName(valid_func);

  auto &entry_block = valid_func.getEntryBlock();
  for (auto &instr : entry_block) {
    auto alloca_inst = llvm::dyn_cast<llvm::AllocaInst>(&instr);
    if (alloca_inst == nullptr) {
      continue;
    }

    auto allocated_type = alloca_inst->getAllocatedType();

    auto type_name = allocated_type->getStructName().str();
    if (type_name == expected_type_name) {
      return alloca_inst;
    }
  }

  return StackFrameSplitErrorCode::StackFrameAllocationNotFound;
}

const llvm::CallInst *
SplitStackFrameAtReturnAddress::GetReturnAddressInstrinsicCall(
    const llvm::Function &valid_func) {
  static const std::string kExpectedCallDestination{"llvm.returnaddress"};

  const auto &entry_block = valid_func.getEntryBlock();
  for (const auto &instr : entry_block) {
    auto call_inst = llvm::dyn_cast<llvm::CallInst>(&instr);
    if (call_inst == nullptr) {
      continue;
    }

    auto intr_id = call_inst->getIntrinsicID();
    if (intr_id == llvm::Intrinsic::returnaddress) {
      return call_inst;
    }
  }

  return nullptr;
}

Result<RetnAddressStoreInstructions, StackFrameSplitErrorCode>
SplitStackFrameAtReturnAddress::GetRetnAddressStoreInstructions(
    llvm::Function &function) {

  RetnAddressStoreInstructions output{};
  if (function.empty()) {
    return output;
  }

  // Look for the one and only instruction that allocates the stack frame
  auto stack_frame_alloca_res = GetStackFrameAllocaInst(function);
  if (!stack_frame_alloca_res.Succeeded()) {
    return stack_frame_alloca_res.TakeError();
  }

  auto stack_frame_alloca = stack_frame_alloca_res.TakeValue();

  // Look for the call to the llvm.returnaddress instrinsic; we need it
  // to identify where we need to split the stack frame
  auto retnaddr_intr_call = GetReturnAddressInstrinsicCall(function);
  if (retnaddr_intr_call == nullptr) {
    return output;
  }

  // Enumerate all the `store` instructions that are saving the
  // llvm.returnaddress value
  auto store_inst_list = TrackUsersOf<llvm::StoreInst>(retnaddr_intr_call);

  // Go through each `store`, and find the one that operates on the
  // `alloca` instruction that we have identified
  using StoreAndOffsetPair = std::pair<const llvm::StoreInst *, std::int64_t>;

  auto module = function.getParent();
  auto data_layout = module->getDataLayout();

  for (const auto &store_inst : store_inst_list) {
    auto store_dest = store_inst->getPointerOperand();

    // Deconstruct the GetElementPointer instruction, then look whether it is
    // operating on the original `alloca` instruction we are tracking
    auto dest_value_offset = remill::StripAndAccumulateConstantOffsets(
        data_layout, const_cast<llvm::Value *>(store_dest));

    const auto dest_value = std::get<0>(dest_value_offset);
    if (dest_value != stack_frame_alloca) {
      continue;
    }

    const auto offset = std::get<1>(dest_value_offset);

    auto store_and_offset = std::make_pair(store_inst, offset);
    output.store_off_pairs.push_back(std::move(store_and_offset));
  }

  output.alloca_inst = stack_frame_alloca;
  return output;
}

Result<std::uint32_t, StackFrameSplitErrorCode>
SplitStackFrameAtReturnAddress::StructOffsetToElementIndex(
    const llvm::Module *module, const llvm::StructType *struct_type,
    std::int64_t offset) {

  auto elem_count = struct_type->getNumElements();
  auto data_layout = module->getDataLayout();

  std::int64_t current_elem_offset{};
  for (auto i = 0U; i < elem_count; ++i) {
    auto elem_type = struct_type->getElementType(i);
    auto elem_size = data_layout.getTypeAllocSize(elem_type);

    if (current_elem_offset == offset) {
      return i;
    }

    current_elem_offset += elem_size;
  }

  return StackFrameSplitErrorCode::StackFrameOffsetError;
}

SuccessOrStackSplitError
SplitStackFrameAtReturnAddress::SplitStackFrameAtOffset(
    llvm::Function &function, std::int64_t offset,
    llvm::AllocaInst *orig_frame_alloca) {

  auto stack_frame_type_res = GetFunctionStackFrameType(function);
  if (!stack_frame_type_res.Succeeded()) {
    return stack_frame_type_res.TakeError();
  }

  auto stack_frame_type = stack_frame_type_res.TakeValue();

  // Attempt to split the function stack frame, isolating the element
  // containing the return address
  auto stack_frame_parts_res =
      SplitStackFrameTypeAtOffset(function, offset, stack_frame_type);

  if (!stack_frame_parts_res.Succeeded()) {
    return stack_frame_parts_res.TakeError();
  }

  auto stack_frame_parts = stack_frame_parts_res.TakeValue();

  if (stack_frame_parts.empty()) {

    // This is not an error, the stack does not need splitting
    return std::monostate();
  }

  // Replace the AllocaInst that creates the original stack frame
  llvm::IRBuilder<> builder(orig_frame_alloca);

  struct StackFrameAlloc final {
    llvm::AllocaInst *alloca_inst{nullptr};
    std::size_t base_index{};
    std::size_t elem_count{};
  };

  std::vector<StackFrameAlloc> stack_frame_allocs;
  std::size_t base_index{};

  for (const auto &stack_frame_part : stack_frame_parts) {
    StackFrameAlloc new_frame;
    new_frame.alloca_inst = builder.CreateAlloca(stack_frame_part);
    new_frame.base_index = base_index;

    new_frame.elem_count = stack_frame_part->getNumElements();
    base_index += new_frame.elem_count;

    stack_frame_allocs.push_back(new_frame);
  }

  // Track down all the GEP instructions operating on the original
  // stack frame allocation
  auto gep_instr_list =
      TrackUsersOf<llvm::GetElementPtrInst>(orig_frame_alloca);

  if (gep_instr_list.empty()) {

    // This is an error. We already know that there is a write, so if
    // we end up inside here then we have failed to track down the
    // instructions we need
    return StackFrameSplitErrorCode::InstructionTrackingError;
  }

  auto module = function.getParent();
  auto data_layout = module->getDataLayout();

  for (auto gep_instr : gep_instr_list) {

    // Translate the GEP instruction to a raw offset
    auto dest_value_offset =
        remill::StripAndAccumulateConstantOffsets(data_layout, gep_instr);

    auto offset = std::get<1>(dest_value_offset);

    // Translate the offset to an element index into the original frame type
    auto orig_elem_index_res =
        StructOffsetToElementIndex(module, stack_frame_type, offset);

    if (!orig_elem_index_res.Succeeded()) {
      return orig_elem_index_res.TakeError();
    }

    auto original_elem_index = orig_elem_index_res.TakeValue();

    // Determine where we need to reroute this GEP instruction
    // There are two different cases to handle:
    // - 2x new frame types: the element we isolated was at the start
    //                       or at the end of the original frame type
    //
    // - 3x new frame types: the element we isolated was in the middle
    //                       of the original frame type

    llvm::AllocaInst *new_frame_part = nullptr;
    std::int32_t new_index = 0;

    for (auto stack_frame_alloc : stack_frame_allocs) {
      if (original_elem_index >= stack_frame_alloc.base_index &&
          original_elem_index <
              stack_frame_alloc.base_index + stack_frame_alloc.elem_count) {

        new_frame_part = stack_frame_alloc.alloca_inst;
        new_index = original_elem_index - stack_frame_alloc.base_index;

        break;
      }
    }

    if (new_frame_part == nullptr) {

      // This is an error, we have failed to locate the alloca instruction
      // for the stack frame replacement
      return StackFrameSplitErrorCode::InternalError;
    }

    // Overwrite the GEP instruction
    llvm::IRBuilder<> builder(gep_instr);
    auto new_destination = builder.CreateGEP(
        new_frame_part, {builder.getInt32(0), builder.getInt32(new_index)});

    gep_instr->replaceAllUsesWith(new_destination);
    gep_instr->eraseFromParent();
  }

  // Now that there are no more usages, we can delete the old AllocaInst
  orig_frame_alloca->eraseFromParent();

  return std::monostate();
}

SplitStackFrameAtReturnAddress::SplitStackFrameAtReturnAddress(
    ITransformationErrorManager &error_manager)
    : BaseFunctionPass(error_manager) {}

llvm::FunctionPass *CreateSplitStackFrameAtReturnAddress(
    ITransformationErrorManager &error_manager) {
  return SplitStackFrameAtReturnAddress::Create(error_manager);
}

}  // namespace anvill
