/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */


#include <anvill/Passes/SplitStackFrameAtReturnAddress.h>

#include <anvill/ABI.h>
#include <anvill/Lifters.h>
#include <anvill/Transforms.h>
#include <glog/logging.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Intrinsics.h>
#include <remill/BC/Util.h>

#include <unordered_set>

#include "Utils.h"

namespace anvill {
namespace {
//
//// Function pass outcome
//enum class StackFrameSplitErrorCode {
//  // The stack frame type was not found
//  StackFrameTypeNotFound,
//
//  // The stack frame allocation instruction was not found
//  StackFrameAllocaInstNotFound,
//
//  // Unexpected stack frame type format
//  UnexpectedStackFrameTypeFormat,
//
//  // Unexpected stack frame usage, causing the instruction tracking to fail
//  UnexpectedStackFrameUsage,
//
//  // The post-transformation verification step has failed
//  TransformationFailed,
//
//  // An unexpected, internal error
//  InternalError,
//
//  // A type could not be defined due to an existing type with
//  // the same name
//  TypeConflict,
//
//  // The function cleanup has failed; some of the GEP instructions could
//  // not be erased since they still had uses that were not replaced
//  // correctly
//  FunctionCleanupError,
//
//  // An error has occurred while the stack frame was split and the
//  // resulting size is not correct
//  InvalidStackFrameSize,
//};
//
//// A Result<> object where the value is not tracked
//using SuccessOrStackFrameSplitErrorCode =
//    Result<std::monostate, StackFrameSplitErrorCode>;
//
//// Contains the necessary information to perform the stack splitting operation
//struct FunctionStackAnalysis final {
//  // Describes a GEP instruction
//  struct GEPInstruction final {
//    // The original instruction
//    llvm::GetElementPtrInst *instr{nullptr};
//
//    // The offset into the structure
//    std::int64_t offset{};
//  };
//
//  // A stack frame part
//  struct StackFramePart final {
//    // Start offset
//    std::int64_t start_offset{};
//
//    // End offset
//    std::int64_t end_offset{};
//
//    // Part size
//    std::int64_t size{};
//  };
//
//  // The stack frame type
//  llvm::StructType *stack_frame_type{nullptr};
//
//  // Stack frame size
//  std::size_t stack_frame_size{};
//
//  // The instruction allocating the stack frame
//  llvm::AllocaInst *stack_frame_alloca{nullptr};
//
//  // The size of a pointer
//  std::size_t pointer_size{};
//
//  // A list of GEP instructions that are operating on the
//  // stack frame
//  std::vector<GEPInstruction> gep_instr_list;
//
//  // A list of new stack frame parts
//  std::vector<StackFramePart> stack_frame_parts;
//};
//
//// Describes an allocated stack frame part
//struct AllocatedStackFramePart final {
//  // The part information, as taken from the stack analysis
//  FunctionStackAnalysis::StackFramePart part_info;
//
//  // The newily create alloca instruction that allocates this
//  // part
//  llvm::AllocaInst *alloca_instr{nullptr};
//};
//
//// A list of allocated stack frame parts
//using AllocatedStackFramePartList = std::vector<AllocatedStackFramePart>;

// Find the `alloca` instruction for the stack frame type.
static llvm::AllocaInst *FindStackFrameAlloca(llvm::Function &func) {
  for (auto &inst : func.getEntryBlock()) {
    auto alloca = llvm::dyn_cast<llvm::AllocaInst>(&inst);
    if (!alloca) {
      continue;
    }

    auto frame_type = llvm::dyn_cast<llvm::StructType>(
        alloca->getAllocatedType());
    if (!frame_type) {
      continue;
    }

    auto frame_name = frame_type->getName();
    if (!frame_name.startswith(func.getName()) ||
        !frame_name.endswith(kStackFrameTypeNameSuffix)) {
      continue;
    }

    return alloca;
  }

  return nullptr;
}

struct FixedOffsetUse {
  llvm::Use *use;
  llvm::APInt offset;
};

// Find all (indirect) uses of the stack frame allocation.
static std::vector<FixedOffsetUse> FindFixedOffsetUses(
    llvm::AllocaInst *alloca) {

  const llvm::DataLayout &dl = alloca->getModule()->getDataLayout();
  const auto addr_size = dl.getIndexSizeInBits(0);

  std::vector<FixedOffsetUse> found;
  std::unordered_set<llvm::Use *> seen;
  std::vector<std::pair<llvm::Instruction *, llvm::APInt>> work_list;
  work_list.emplace_back(alloca, llvm::APInt(addr_size, 0u, true));

  auto add_to_found = [&found] (llvm::Use &use,
      llvm::APInt offset) {
    FixedOffsetUse fou;
    fou.offset = std::move(offset);
    fou.use = &use;
    found.emplace_back(std::move(fou));
  };

  while (!work_list.empty()) {
    auto [inst, offset] = work_list.back();
    work_list.pop_back();

    for (llvm::Use &use : inst->uses()) {
      if (seen.count(&use)) {
        continue;
      }

      add_to_found(use, offset);

      auto user_inst = llvm::dyn_cast<llvm::Instruction>(use.getUser());
      if (!user_inst) {
        continue;
      }

      switch (user_inst->getOpcode()) {
        default:
          break;
        case llvm::Instruction::BitCast:
        case llvm::Instruction::PtrToInt:
        case llvm::Instruction::IntToPtr:
          work_list.emplace_back(user_inst, offset);
          break;
        case llvm::Instruction::GetElementPtr: {
          auto gep = llvm::dyn_cast<llvm::GetElementPtrInst>(user_inst);
          llvm::APInt sub_offset(addr_size, offset.getSExtValue(), true);
          if (gep->accumulateConstantOffset(dl, sub_offset)) {
            work_list.emplace_back(gep, std::move(sub_offset));
          }
        }
      }
    }
  }

  return found;
}

static void AnnotateStackUses(llvm::AllocaInst *frame_alloca,
                              const std::vector<FixedOffsetUse> &uses,
                              const StackFrameRecoveryOptions &options) {
  auto zero = frame_alloca->getMetadata(kAnvillStackZero);
  if (!zero) {
    return;
  }

  auto zero_md = llvm::dyn_cast<llvm::ValueAsMetadata>(zero->getOperand(0u));
  if (!zero_md) {
    return;
  }

  auto zero_val = llvm::dyn_cast<llvm::ConstantInt>(zero_md->getValue());
  if (!zero_val) {
    return;
  }

  auto &context = frame_alloca->getContext();
  auto md_id = context.getMDKindID(options.stack_offset_metadata_name);

  auto zero_offset = zero_val->getSExtValue();
  auto create_metadata =
      [=, &context] (llvm::Instruction *inst, int64_t offset) {
        int64_t disp = 0;
        if (options.stack_grows_down) {
          disp = zero_offset - offset;
        } else {
          disp = offset - zero_offset;
        }

        auto disp_val = llvm::ConstantInt::get(
            zero_val->getType(), static_cast<uint64_t>(disp), true);
        auto disp_md = llvm::ValueAsMetadata::get(disp_val);
        return llvm::MDNode::get(context, disp_md);
      };

  // Annotate the used instructions.
  for (const auto &use : uses) {
    auto inst = llvm::dyn_cast<llvm::Instruction>(use.use->get());
    if (!inst || inst->getMetadata(md_id)) {
      continue;  // Not an instruction, or already annotated.
    }

    auto offset = use.offset.getSExtValue();
    auto md = create_metadata(inst, offset);

    inst->setMetadata(md_id, md);

//    // Also apply the metadata to loads/stores.
//    if (auto user = llvm::dyn_cast<llvm::Instruction>(use.use->getUser())) {
//      switch (user->getOpcode()) {
//        case llvm::Instruction::Load:
//        case llvm::Instruction::Store:
//          user->setMetadata(md_id, md);
//          break;
//      }
//    }
  }
}

//
//// Analyses the function to determine the necessary steps to split
//// the function's stack frame
//static Result<FunctionStackAnalysis, StackFrameSplitErrorCode>
//AnalyzeFunction(llvm::Function &function) {
//  FunctionStackAnalysis output;
//
//
//
//
//  // Get the stack frame structure for this function. This also
//  // validates its format
//  auto stack_frame_type_res = GetFunctionStackFrameType(function);
//  if (!stack_frame_type_res.Succeeded()) {
//    auto error = stack_frame_type_res.TakeError();
//    if (error == StackFrameSplitErrorCode::StackFrameTypeNotFound) {
//      return output;
//    }
//
//    return error;
//  }
//
//  output.stack_frame_type = stack_frame_type_res.TakeValue();
//
//  // Look for the `AllocaInst` that is allocating the stack frame
//  auto alloca_inst_list = SelectInstructions<llvm::AllocaInst>(function);
//
//  auto alloca_inst_it = std::find_if(
//      alloca_inst_list.begin(), alloca_inst_list.end(),
//
//      [&](const llvm::Instruction *inst) -> bool {
//        auto alloca_inst = llvm::dyn_cast<const llvm::AllocaInst>(inst);
//        auto allocated_type = alloca_inst->getAllocatedType();
//
//        return (allocated_type == output.stack_frame_type);
//      });
//
//  if (alloca_inst_it == alloca_inst_list.end()) {
//    // The stack frame type was found, so we must have failed to
//    // track down the correct instruction
//    return StackFrameSplitErrorCode::StackFrameAllocaInstNotFound;
//  }
//
//  output.stack_frame_alloca = llvm::dyn_cast<llvm::AllocaInst>(*alloca_inst_it);
//
//  // Get the `__anvill_ra` global variable
//  auto &module = *function.getParent();
//
//  auto symbolic_value = module.getGlobalVariable(kSymbolicRAName);
//  if (symbolic_value == nullptr) {
//    return output;
//  }
//
//  // Track down all the `StoreInst` instructions using the return address
//  auto anvill_ra_value = llvm::dyn_cast<llvm::User>(symbolic_value);
//
//  auto anvill_ra_users = TrackUsersOf<llvm::StoreInst>(anvill_ra_value);
//  if (anvill_ra_users.empty()) {
//    return output;
//  }
//
//  // Extract the GEPs that are used to write the return address from the
//  // list of store instructions we have found
//  auto data_layout = module.getDataLayout();
//
//  output.stack_frame_size =
//      data_layout.getTypeAllocSize(output.stack_frame_type);
//
//  output.pointer_size = data_layout.getPointerSizeInBits(0) / 8U;
//
//  std::vector<FunctionStackAnalysis::GEPInstruction> retn_addr_gep_instructions;
//
//  for (auto inst : anvill_ra_users) {
//    auto store_inst = llvm::dyn_cast<llvm::StoreInst>(inst);
//    auto store_dest = store_inst->getPointerOperand();
//
//    // Walk the store dest value until we find the GEP instruction, then
//    // extract its pointer operand
//    auto store_dest_details =
//        remill::StripAndAccumulateConstantOffsets(data_layout, store_dest);
//
//    auto store_ptr_operand = std::get<0>(store_dest_details);
//
//    // Make sure that the pointer value is an `AllocaInst` instruction
//    auto alloca_inst = llvm::dyn_cast<llvm::AllocaInst>(store_ptr_operand);
//    if (alloca_inst == nullptr) {
//      continue;
//    }
//
//    // Discard this instruction unless it's the one that allocates
//    // the stack frame
//    if (output.stack_frame_alloca != alloca_inst) {
//      continue;
//    }
//
//    // Validate the write size
//    auto store_value_type = store_inst->getValueOperand()->getType();
//
//    auto store_value_size = data_layout.getTypeAllocSize(store_value_type);
//    if (store_value_size != output.pointer_size) {
//      return StackFrameSplitErrorCode::UnexpectedStackFrameUsage;
//    }
//
//    // The GEP instruction should be the store destination.
//    //
//    // The stack frame generated by the `RecoverBasicStackFrame`
//    // function pass always performs a bitcast after the GEP:
//    //
//    // clang-format off
//    //
//    //   %93 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 28
//    //   %94 = bitcast i8* %93 to i32*
//    //   store i32 ptrtoint (i8* @__anvill_ra to i32), i32* %94, align 4
//    //
//    // clang-format on
//
//    auto bitcast_instr = llvm::dyn_cast<llvm::BitCastOperator>(store_dest);
//    if (bitcast_instr == nullptr) {
//      return StackFrameSplitErrorCode::UnexpectedStackFrameUsage;
//    }
//
//    auto bitcast_operand = bitcast_instr->getOperand(0U);
//
//    auto gep_instr = llvm::dyn_cast<llvm::GetElementPtrInst>(bitcast_operand);
//    if (gep_instr == nullptr) {
//      return StackFrameSplitErrorCode::UnexpectedStackFrameUsage;
//    }
//
//    FunctionStackAnalysis::GEPInstruction entry;
//    entry.instr = gep_instr;
//    entry.offset = std::get<1>(store_dest_details);
//
//    retn_addr_gep_instructions.push_back(std::move(entry));
//  }
//
//  // Each GEP instruction we have found identifies a store of the return
//  // address. Go through each one of them and precompute the new stack
//  // frame parts
//
//  // clang-format on
//  std::sort(retn_addr_gep_instructions.begin(),
//            retn_addr_gep_instructions.end(),
//
//            [](const FunctionStackAnalysis::GEPInstruction &lhs,
//               const FunctionStackAnalysis::GEPInstruction &rhs) -> bool {
//              return lhs.offset < rhs.offset;
//            });
//  // clang-format off
//
//  std::unordered_set<std::int64_t> visited_offsets;
//  std::int64_t current_offset{};
//
//  for (auto &gep : retn_addr_gep_instructions) {
//    if (visited_offsets.count(gep.offset) > 0U) {
//      continue;
//    }
//
//    visited_offsets.insert(gep.offset);
//
//    auto leading_part = gep.offset - current_offset;
//    if (leading_part != 0) {
//      FunctionStackAnalysis::StackFramePart part;
//      part.start_offset = current_offset;
//      part.end_offset = gep.offset - 1;
//      part.size = leading_part;
//
//      output.stack_frame_parts.push_back(std::move(part));
//    }
//
//    FunctionStackAnalysis::StackFramePart part;
//    part.size = output.pointer_size;
//    part.start_offset = gep.offset;
//    part.end_offset = part.start_offset + part.size - 1U;
//
//    current_offset = part.end_offset + 1U;
//    output.stack_frame_parts.push_back(std::move(part));
//  }
//
//  auto remaining_bytes = output.stack_frame_size - current_offset;
//  if (remaining_bytes != 0) {
//    FunctionStackAnalysis::StackFramePart part;
//    part.size = remaining_bytes;
//    part.start_offset = current_offset;
//    part.end_offset = part.start_offset + part.size;
//
//    output.stack_frame_parts.push_back(std::move(part));
//  }
//
//  // Track down all the GEP instructions we have to rewrite
//  auto stack_frame_gep_list = TrackUsersOf<llvm::GetElementPtrInst>(output.stack_frame_alloca);
//  if (stack_frame_gep_list.empty()) {
//    return StackFrameSplitErrorCode::InternalError;
//  }
//
//  for (auto stack_frame_gep : stack_frame_gep_list) {
//    auto gep_instr = llvm::dyn_cast<llvm::GetElementPtrInst>(stack_frame_gep);
//
//    auto store_dest_details = remill::StripAndAccumulateConstantOffsets(data_layout, gep_instr);
//
//    auto alloca_inst = llvm::dyn_cast<llvm::AllocaInst>(std::get<0>(store_dest_details));
//    if (alloca_inst == nullptr || alloca_inst != output.stack_frame_alloca) {
//      continue;
//    }
//
//    FunctionStackAnalysis::GEPInstruction entry;
//    entry.instr = gep_instr;
//    entry.offset = std::get<1>(store_dest_details);
//
//    output.gep_instr_list.push_back(std::move(entry));
//  }
//
//  return output;
//}
//
//// Updates the function to split the stack frame usage around the
//// return address value
//static SuccessOrStackFrameSplitErrorCode SplitStackFrame(
//    llvm::Function &function, const FunctionStackAnalysis &stack_analysis) {
//
//  if (stack_analysis.gep_instr_list.empty()) {
//    return std::monostate();
//  }
//
//  //
//  // Allocate the new stack frame parts
//  //
//
//  auto &module = *function.getParent();
//  auto &context = module.getContext();
//  auto data_layout = module.getDataLayout();
//
//  auto byte_type = llvm::Type::getInt8Ty(context);
//
//  llvm::IRBuilder<> builder(stack_analysis.stack_frame_alloca);
//
//  AllocatedStackFramePartList allocated_part_list;
//  std::size_t allocated_stack_parts_size{};
//
//  for (const auto &part_info : stack_analysis.stack_frame_parts) {
//    // First, create the type
//    auto byte_array_type = llvm::ArrayType::get(byte_type, part_info.size);
//    if (byte_array_type == nullptr) {
//      return StackFrameSplitErrorCode::InternalError;
//    }
//
//    auto part_name =
//        GenerateStackFramePartTypeName(function, allocated_part_list.size());
//
//    if (getTypeByName(module, part_name) != nullptr) {
//      return StackFrameSplitErrorCode::TypeConflict;
//    }
//
//    auto part_type =
//        llvm::StructType::create({byte_array_type}, part_name, true);
//
//    if (part_type == nullptr) {
//      return StackFrameSplitErrorCode::InternalError;
//    }
//
//    allocated_stack_parts_size += data_layout.getTypeAllocSize(part_type);
//
//    // Then, write the new `AllocaInst` instruction
//    auto alloca_instr = builder.CreateAlloca(part_type);
//
//    // Save this stack frame part for later, we'll need it to replace
//    // the usages
//    AllocatedStackFramePart allocated_frame_part;
//    allocated_frame_part.part_info = part_info;
//    allocated_frame_part.alloca_instr = alloca_instr;
//
//    allocated_part_list.push_back(allocated_frame_part);
//  }
//
//  // Double check the total size
//  if (allocated_stack_parts_size != stack_analysis.stack_frame_size) {
//    return StackFrameSplitErrorCode::InvalidStackFrameSize;
//  }
//
//  //
//  // Replace the instructions
//  //
//
//  // Write the new GEP instructions
//  for (auto &gep_instr : stack_analysis.gep_instr_list) {
//    // Locate which stack frame part we need to use based on the offset
//    // being accessed
//    auto part_it = std::find_if(
//        allocated_part_list.begin(), allocated_part_list.end(),
//
//        [&](const AllocatedStackFramePart &allocated_part) -> bool {
//          if (gep_instr.offset >= allocated_part.part_info.start_offset &&
//              gep_instr.offset <= allocated_part.part_info.end_offset) {
//            return true;
//          }
//
//          return false;
//        }
//    );
//
//    if (part_it == allocated_part_list.end()) {
//      return StackFrameSplitErrorCode::InternalError;
//    }
//
//    auto stack_frame_part = *part_it;
//
//    // Write a new GEP instruction that accesses the correct
//    // stack frame part
//    builder.SetInsertPoint(gep_instr.instr);
//
//    auto offset = static_cast<std::int32_t>(
//        gep_instr.offset - stack_frame_part.part_info.start_offset);
//
//    auto new_gep = builder.CreateGEP(
//        stack_frame_part.alloca_instr,
//        {builder.getInt32(0), builder.getInt32(0), builder.getInt32(offset)});
//
//    CopyMetadataTo(gep_instr.instr, new_gep);
//    gep_instr.instr->replaceAllUsesWith(new_gep);
//  }
//
//  //
//  // Remove the instructions we no longer need
//  //
//
//  // We should be able to delete all the the GEP instructions
//  std::size_t erased_gep_instr_count{};
//
//  for (auto &gep_instr : stack_analysis.gep_instr_list) {
//    if (!gep_instr.instr->use_empty()) {
//      continue;
//    }
//
//    ++erased_gep_instr_count;
//    gep_instr.instr->eraseFromParent();
//  }
//
//  if (erased_gep_instr_count != stack_analysis.gep_instr_list.size()) {
//    return StackFrameSplitErrorCode::FunctionCleanupError;
//  }
//
//  // The original alloca instruction may still be in use; replace those
//  // usages with the first stack frame part
//  if (!stack_analysis.stack_frame_alloca->use_empty()) {
//    auto &first_stack_frame_part = allocated_part_list.front();
//    CopyMetadataTo(stack_analysis.stack_frame_alloca, first_stack_frame_part.alloca_instr);
//
//    stack_analysis.stack_frame_alloca->replaceAllUsesWith(
//        first_stack_frame_part.alloca_instr);
//  }
//
//  if (!stack_analysis.stack_frame_alloca->use_empty()) {
//    return StackFrameSplitErrorCode::FunctionCleanupError;
//  }
//
//  stack_analysis.stack_frame_alloca->eraseFromParent();
//
//  //
//  // Verify the original stack frame type is no longer used
//  //
//
//  // Double check that no one is using the original stack frame type
//  // anymore
//  auto instr_list =
//      SelectInstructions<llvm::AllocaInst, llvm::GetElementPtrInst>(function);
//
//  for (const auto &instr : instr_list) {
//    if (auto alloca_instr = llvm::dyn_cast<llvm::AllocaInst>(instr);
//        alloca_instr != nullptr) {
//      if (alloca_instr->getAllocatedType() == stack_analysis.stack_frame_type) {
//        return StackFrameSplitErrorCode::TransformationFailed;
//      }
//
//    } else if (auto gep_instr = llvm::dyn_cast<llvm::GetElementPtrInst>(instr);
//               gep_instr != nullptr) {
//      if (gep_instr->getPointerOperandType() ==
//          stack_analysis.stack_frame_type) {
//        return StackFrameSplitErrorCode::TransformationFailed;
//      }
//    }
//  }
//
//  return std::monostate();
//}
//
//// Returns the name of the stack frame type for the given function
//static std::string GetFunctionStackFrameTypeName(
//    const llvm::Function &function) {
//  return function.getName().str() + kStackFrameTypeNameSuffix;
//}
//
//// Returns the stack frame type for the given function
//static Result<llvm::StructType *, StackFrameSplitErrorCode>
//GetFunctionStackFrameType(const llvm::Function &function) {
//
//  auto module = function.getParent();
//
//  auto type = getTypeByName(*module, GetFunctionStackFrameTypeName(function));
//  if (type == nullptr) {
//    return StackFrameSplitErrorCode::StackFrameTypeNotFound;
//  }
//
//  auto struct_type = llvm::dyn_cast<llvm::StructType>(type);
//  if (struct_type == nullptr) {
//    return StackFrameSplitErrorCode::UnexpectedStackFrameTypeFormat;
//  }
//
//  // This stack frame must be a struct containing an array of i8 integers
//  if (struct_type->getNumElements() != 1U) {
//    return StackFrameSplitErrorCode::UnexpectedStackFrameTypeFormat;
//  }
//
//  auto inner_type = struct_type->getElementType(0U);
//  if (!inner_type->isArrayTy()) {
//    return StackFrameSplitErrorCode::UnexpectedStackFrameTypeFormat;
//  }
//
//  auto inner_array = llvm::dyn_cast<llvm::ArrayType>(inner_type);
//  if (inner_array->getElementType() !=
//      llvm::Type::getInt8Ty(module->getContext())) {
//    return StackFrameSplitErrorCode::UnexpectedStackFrameTypeFormat;
//  }
//
//  return struct_type;
//}
//
//// Generates a new name for a stack frame part
//static std::string GenerateStackFramePartTypeName(
//    const llvm::Function &function, std::size_t part_number) {
//  return function.getName().str() + kStackFrameTypeNameSuffix + "_part" +
//         std::to_string(part_number);
//}

}  // namespace

llvm::PreservedAnalyses
SplitStackFrameAtReturnAddress::run(llvm::Function &function,
                                    llvm::FunctionAnalysisManager &fam) {
  if (function.isDeclaration()) {
    return llvm::PreservedAnalyses::all();
  }

  auto frame_alloca = FindStackFrameAlloca(function);
  if (!frame_alloca) {
    return llvm::PreservedAnalyses::all();
  }

  auto uses = FindFixedOffsetUses(frame_alloca);
  if (uses.empty()) {
    return llvm::PreservedAnalyses::all();  // This is strange.
  }

  if (options.stack_offset_metadata_name) {
    AnnotateStackUses(frame_alloca, uses, options);
  }

  return llvm::PreservedAnalyses::none();

//  // Analyze the function first; there may be nothing to do
//  auto analysis_res = AnalyzeFunction(function);
//  if (!analysis_res.Succeeded()) {
//    auto error = analysis_res.TakeError();
//    if (error == StackFrameSplitErrorCode::StackFrameTypeNotFound ||
//        error == StackFrameSplitErrorCode::StackFrameAllocaInstNotFound) {
//      return false;
//    }
//
//    EmitError(SeverityType::Error, analysis_res.TakeError(),
//              "The function analysis has failed");
//
//    return false;
//  }
//
//  auto analysis = analysis_res.TakeValue();
//  if (analysis.gep_instr_list.empty()) {
//    return false;
//  }
//
//  // Attempt to split the stack frame
//  auto split_res = SplitStackFrame(function, analysis);
//  if (!split_res.Succeeded()) {
//    EmitError(SeverityType::Fatal, split_res.TakeError(),
//              "The stack frame splitting has failed");
//
//    return true;
//  }
//
//  // Do a second analysis, this time it should fail since we deleted
//  // the `AllocaInst` that we we would expect to find
//  analysis_res = AnalyzeFunction(function);
//  if (analysis_res.Succeeded()) {
//    EmitError(
//        SeverityType::Fatal, StackFrameSplitErrorCode::TransformationFailed,
//        "The second function analysis has found unreplaced stack frame usages");
//
//    return true;
//  }
//
//  // Make sure that the returned error is the correct one; the type should
//  // still be defined, but the origin AllocaInst should no longer be present
//  auto analysis_error = analysis_res.TakeError();
//  if (analysis_error !=
//      StackFrameSplitErrorCode::StackFrameAllocaInstNotFound) {
//
//    EmitError(
//        SeverityType::Fatal, analysis_error,
//        "Failed to verify the correctness of the function transformation");
//
//    return true;
//  }
//
//  return true;
}

llvm::StringRef SplitStackFrameAtReturnAddress::name(void) {
  return llvm::StringRef("SplitStackFrameAtReturnAddress");
}

void AddSplitStackFrameAtReturnAddress(
    llvm::FunctionPassManager &fpm, const StackFrameRecoveryOptions &options) {
  fpm.addPass(SplitStackFrameAtReturnAddress(options));
}

}  // namespace anvill
