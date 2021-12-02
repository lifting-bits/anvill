/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Passes/RecoverBasicStackFrame.h>

#include <anvill/ABI.h>
#include <anvill/CrossReferenceFolder.h>
#include <anvill/CrossReferenceResolver.h>
#include <anvill/Lifters.h>
#include <glog/logging.h>
#include <remill/BC/Util.h>

#include <cassert>
#include <iostream>
#include <limits>
#include <vector>

#include "Utils.h"

namespace anvill {
namespace {


// Describes an instruction that accesses the stack pointer through the
// `__anvill_sp` symbol.
struct StackPointerUse final {
  inline explicit StackPointerUse(llvm::Use *use_, std::uint64_t type_size_,
                                  std::int64_t stack_offset_)
      : use(use_),
        type_size(type_size_),
        stack_offset(stack_offset_) {}

  // An operand inside of a particular instruction, where `use->getUser()`
  // is an `llvm::Instruction`, and `use->get()` is a value related to the
  // stack pointer.
  llvm::Use *const use;

  // Operand size
  const std::uint64_t type_size;

  // Stack offset referenced
  const std::int64_t stack_offset;
};

// Contains a list of `load` and `store` instructions that reference
// the stack pointer
using StackPointerRegisterUsages = std::vector<llvm::Use *>;

// This structure contains the stack size, along with the lower and
// higher bounds of the offsets, and all the instructions that have
// been analyzed
struct StackFrameAnalysis final {

  // A list of uses that reference the stack pointer
  std::vector<StackPointerUse> instruction_uses;

  // Lowest SP-relative offset
  std::int64_t lowest_offset{};

  // Highest SP-relative offset
  std::int64_t highest_offset{};

  // Stack frame size
  std::size_t size{};
};

// Enumerates all the store and load instructions that reference
// the stack
static StackPointerRegisterUsages EnumerateStackPointerUsages(
    llvm::Function &function) {
  StackPointerRegisterUsages output;

  auto module = function.getParent();

  for (auto &basic_block : function) {
    for (auto &instr : basic_block) {
      for (auto i = 0u, num_ops = instr.getNumOperands(); i < num_ops; ++i) {
        auto &use = instr.getOperandUse(i);
        if (auto val = use.get(); IsRelatedToStackPointer(module, val)) {
          output.emplace_back(&use);
        }
      }
    }
  }

  return output;
}

static constexpr uint64_t kMax16 = std::numeric_limits<uint16_t>::max();
static constexpr uint64_t kMax32 = std::numeric_limits<uint32_t>::max();

// Analyzes the stack frame, determining the relative boundaries and
// collecting the instructions that operate on the stack pointer
static StackFrameAnalysis AnalyzeStackFrame(
    llvm::Function &function, const StackFrameRecoveryOptions &options) {

  // The CrossReferenceResolver can accumulate all the offsets
  // applied to the stack pointer symbol for us
  auto module = function.getParent();
  auto &data_layout = module->getDataLayout();

  NullCrossReferenceResolver resolver;
  CrossReferenceFolder folder(resolver, data_layout);

  // Pre-initialize the stack limits
  StackFrameAnalysis output;
  output.highest_offset = std::numeric_limits<std::int64_t>::min();
  output.lowest_offset = std::numeric_limits<std::int64_t>::max();

  // Go through each one of the instructions we have found
  for (const auto use : EnumerateStackPointerUsages(function)) {

    // Skip any operand that is not related to the stack pointer
    const auto val = use->get();

    // Attempt to resolve the constant expression into an offset
    const auto reference = folder.TryResolveReferenceWithClearedCache(val);
    if (!reference.is_valid || !reference.references_stack_pointer) {
      continue;
    }

    // The offset from the stack pointer. Force to a 32-bit, then sign-extend.
    int64_t stack_offset = reference.Displacement(data_layout);
    if (options.max_stack_frame_size <= kMax16) {
      stack_offset = static_cast<int16_t>(stack_offset);
    } else if (options.max_stack_frame_size <= kMax32) {
      stack_offset = static_cast<int32_t>(stack_offset);
    }

    // Update the boundaries, based on the offset we have found
    std::uint64_t type_size =
        data_layout.getTypeAllocSize(val->getType()).getFixedSize();

    // In the case of `store` instructions, we want to record the size of the
    // stored value as the type size or updating the stack offset.
    if (auto store = llvm::dyn_cast<llvm::StoreInst>(use->getUser())) {
      if (use->getOperandNo() == 1) {
        const auto stored_type = store->getValueOperand()->getType();
        type_size = data_layout.getTypeAllocSize(stored_type).getFixedSize();
      }

      // In the case of `load` instructions, we want to redord the size of the
      // loaded value.
    } else if (auto load = llvm::dyn_cast<llvm::LoadInst>(use->getUser())) {
      type_size = data_layout.getTypeAllocSize(load->getType()).getFixedSize();
    }

    output.highest_offset =
        std::max(output.highest_offset,
                 stack_offset + static_cast<std::int64_t>(type_size));

    output.lowest_offset = std::min(output.lowest_offset, stack_offset);

    // Save the operand use.
    output.instruction_uses.emplace_back(use, type_size, stack_offset);
  }

  output.size =
      static_cast<std::size_t>(output.highest_offset - output.lowest_offset);

  return output;
}

// Generates a simple, byte-array based, stack frame for the given
// function
static llvm::StructType *GenerateStackFrameType(
    const llvm::Function &function, const StackFrameRecoveryOptions &options,
    const StackFrameAnalysis &stack_frame_analysis, std::size_t padding_bytes) {

  // Generate a stack frame type with a name that matches the anvill ABI
  auto function_name = function.getName().str();
  auto stack_frame_type_name = function_name + kStackFrameTypeNameSuffix;

  // Make sure this type is not defined already
  auto module = function.getParent();
  const auto &dl = module->getDataLayout();
  auto &context = module->getContext();

  auto stack_frame_type = llvm::StructType::getTypeByName(
      context, stack_frame_type_name);

  // Determine how many bytes we should allocate. We may have been
  // asked to add some additional padding. We don't care how it is
  // accessed right now, we just add to the total size of the final
  // stack frame
  auto stack_frame_size = std::max<uint64_t>(
      1u,
      std::min<uint64_t>(options.max_stack_frame_size,
                         padding_bytes + stack_frame_analysis.size));

  // Round the stack frame to a multiple of the address size.
  auto address_size = dl.getPointerSize(0);
  const auto num_slots = (stack_frame_size + (address_size - 1u)) /
                         address_size;
  stack_frame_size = num_slots * address_size;

  if (stack_frame_type != nullptr) {
    assert(dl.getTypeAllocSize(stack_frame_type).getKnownMinSize() <=
           stack_frame_size);
    return stack_frame_type;
  }

  // Generate the stack frame using an array of address-sized elements.
  auto addr_type = llvm::Type::getIntNTy(context, address_size * 8u);
  auto arr_type = llvm::ArrayType::get(addr_type, num_slots);

  llvm::Type *stack_frame_types[] = {arr_type};
  return llvm::StructType::create(stack_frame_types, stack_frame_type_name);
}

// Generates a new symbolic stack value.
static llvm::GlobalVariable *GetStackSymbolicByteValue(
    llvm::Module &module, const StackFrameRecoveryOptions &options,
    std::int32_t offset, llvm::IntegerType *type) {

  // Create a new name
  auto value_name = kSymbolicStackFrameValuePrefix;
  if (options.stack_grows_down) {
    if (offset < 0) {
      value_name += "plus_";
    } else if (offset > 0) {
      value_name += "minus_";
    }
  } else {
    if (offset < 0) {
      value_name += "minus_";
    } else if (offset > 0) {
      value_name += "plus_";
    }
  }

  value_name += std::to_string(abs(offset));

  auto gv = module.getGlobalVariable(value_name);
  if (gv) {
    assert(gv->getValueType() == type);
    return gv;
  } else {
    return new llvm::GlobalVariable(
        module, type, false, llvm::GlobalValue::ExternalLinkage, nullptr,
        value_name);
  }
}

// Patches the function, replacing the load/store instructions so that
// they operate on the new stack frame type we generated.
static void UpdateFunction(
    llvm::Function &function, const StackFrameRecoveryOptions &options,
    const StackFrameAnalysis &stack_frame_analysis) {

  StackFrameStructureInitializationProcedure init_strategy =
      options.stack_frame_struct_init_procedure;

  std::size_t stack_frame_lower_padding =
      options.stack_frame_lower_padding;

  std::size_t stack_frame_higher_padding =
      options.stack_frame_higher_padding;

  // Generate a new stack frame type, using a byte array inside a
  // StructType
  auto padding_bytes = stack_frame_lower_padding + stack_frame_higher_padding;

  auto stack_frame_type = GenerateStackFrameType(
      function, options, stack_frame_analysis, padding_bytes);

  auto &context = function.getContext();
  auto module = function.getParent();
  const auto &dl = module->getDataLayout();
  auto address_size = dl.getPointerSize(0);
  auto addr_type = llvm::Type::getIntNTy(context, address_size * 8u);

  int64_t base_stack_offset;
  if (options.stack_grows_down) {
    base_stack_offset = stack_frame_analysis.lowest_offset -
                        static_cast<std::int32_t>(stack_frame_lower_padding);
  } else {
    base_stack_offset = stack_frame_analysis.lowest_offset -
                        static_cast<std::int32_t>(stack_frame_lower_padding);
  }

  // Take the first instruction as an insert pointer for the
  // IRBuilder, and then create an `alloca` instruction to
  // generate our new stack frame
  auto &entry_block = function.getEntryBlock();
  auto &insert_point = *entry_block.getFirstInsertionPt();

  llvm::IRBuilder<> builder(&insert_point);
  auto stack_frame_alloca = builder.CreateAlloca(stack_frame_type);

  // Annotate the stack.
  if (options.stack_offset_metadata_name) {

    // TODO(pag): Account for the stack size having actually been clamped down
    //            to a smaller range.

    int64_t base = 0;

    // If the stack grows down, the higher offsets represent accesses to
    // the callee's stack frame. These will be positive.
    if (options.stack_grows_down) {
      base = stack_frame_analysis.highest_offset;
      base += static_cast<int64_t>(options.stack_frame_higher_padding);
      base -= static_cast<int64_t>(address_size);

    // If the stack grows up, the lower offsets represent accesses to the
    // callee's stack frame. These will be negative.
    } else {
      base = stack_frame_analysis.lowest_offset;
      base -= static_cast<int64_t>(options.stack_frame_lower_padding);
      base += static_cast<int64_t>(address_size);
    }

    // NOTE(pag): Base points to the highest or lowest address-sized integer
    //            that can be stored on the stack.

    auto md_id = context.getMDKindID(kAnvillStackZero);
    auto adjust_val = llvm::ConstantInt::get(
        addr_type, static_cast<uint64_t>(base), true);
    auto adjust_md = llvm::ValueAsMetadata::get(adjust_val);
    stack_frame_alloca->setMetadata(
        md_id, llvm::MDNode::get(context, adjust_md));
  }

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
  //     [__anvill_stack_plus_3    <- optional higher padding <- alloca
  //
  //     __anvill_stack_plus_2
  //     __anvill_stack_plus_1
  //     __anvill_stack_0          <- __anvill_sp
  //     __anvill_stack_minus_1
  //     __anvill_stack_minus_2
  //
  //     [__anvill_stack_minus_3   <- optional lower padding
  //
  //     [lower addresses]

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

      for (auto i = 0U; i < total_stack_frame_size; i += address_size) {
        gep_indexes[2] = builder.getInt32(i / address_size);
        auto stack_frame_byte =
            builder.CreateGEP(stack_frame_alloca, gep_indexes);

        auto symbolic_value_ptr = GetStackSymbolicByteValue(
            module, options, current_offset, addr_type);

        current_offset += static_cast<int>(address_size);

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
  // operand uses we have to update.
  for (auto &sp_use : stack_frame_analysis.instruction_uses) {

    const auto obj = sp_use.use->get();

    // Convert the `__anvill_sp`-relative offset to a 0-based index
    // into our stack frame type
    auto zero_based_offset =
        sp_use.stack_offset - stack_frame_analysis.lowest_offset;

    // If we added padding, adjust the displacement value. We just have
    // to add the amount of bytes we have inserted before the stack pointer
    zero_based_offset += stack_frame_lower_padding;

    // Create a GEP instruction that accesses the new stack frame we
    // created based on the relative offset
    //
    // GEP indices for the stack_frame_ptr are constants. It can safely
    // inserted after the alloca instead of before the instruction using
    // it.
    //
    // As a reminder, the stack frame type is a StructType that contains
    // an ArrayType with int8 elements
    llvm::Value *stack_frame_ptr = builder.CreateGEP(
        stack_frame_alloca,
        {builder.getInt32(0), builder.getInt32(0),
         builder.getInt32(zero_based_offset / address_size)});

    auto from_val = sp_use.use->get();
    CopyMetadataTo(from_val, stack_frame_ptr);

    llvm::PointerType *ptr_type = nullptr;
    unsigned scale = 0;
    auto missing = static_cast<uint64_t>(zero_based_offset) % address_size;
    switch (missing) {
      case 7:
      case 5:
      case 3:
      case 1:
        ptr_type = llvm::Type::getInt8PtrTy(context, 0);
        scale = 1;
        break;

      case 4:
        ptr_type = llvm::Type::getInt32PtrTy(context, 0);
        scale = 4;
        break;

      case 6:
      case 2:
        ptr_type = llvm::Type::getInt16PtrTy(context, 0);
        scale = 2;
        break;
      case 0:
        break;
      default:
        LOG(FATAL)
            << "Unsupported address size: " << address_size;
        break;
    }

    if (ptr_type) {
      stack_frame_ptr = builder.CreateBitOrPointerCast(
          stack_frame_ptr, ptr_type);
      CopyMetadataTo(from_val, stack_frame_ptr);
      stack_frame_ptr = builder.CreateGEP(
          stack_frame_alloca, builder.getInt32(missing / scale));
      CopyMetadataTo(from_val, stack_frame_ptr);
    }

    stack_frame_ptr =
        builder.CreateBitOrPointerCast(stack_frame_ptr, obj->getType());
    CopyMetadataTo(from_val, stack_frame_ptr);

    // We now have to replace the operand; it is not correct to use
    // `replaceAllUsesWith` on the operand, because the scope of a constant
    // could be bigger than just the function we are using.
    sp_use.use->set(stack_frame_ptr);
  }
}

}  // namespace

llvm::PreservedAnalyses RecoverBasicStackFrame::run(
    llvm::Function &function, llvm::FunctionAnalysisManager &fam) {
  if (function.isDeclaration()) {
    return llvm::PreservedAnalyses::all();
  }

  // Analyze the stack frame first, enumerating the instructions referencing
  // the __anvill_sp symbol and determining the boundaries of the stack memory
  StackFrameAnalysis stack_frame_analysis = AnalyzeStackFrame(function, options);
  if (stack_frame_analysis.instruction_uses.empty()) {
    return llvm::PreservedAnalyses::all();
  }

  // It is now time to patch the function. This method will take the stack
  // analysis and use it to generate a stack frame type and update all the
  // instructions
  UpdateFunction(function, options, stack_frame_analysis);

  // Analyze the __anvill_sp usage again; this time, the resulting
  // instruction list should be empty
  assert(EnumerateStackPointerUsages(function).empty());

  return llvm::PreservedAnalyses::none();
}

llvm::StringRef RecoverBasicStackFrame::name(void) {
  return llvm::StringRef("RecoverBasicStackFrame");
}

void AddRecoverBasicStackFrame(llvm::FunctionPassManager &fpm,
                               const StackFrameRecoveryOptions &options) {
  fpm.addPass(RecoverBasicStackFrame(options));
}
}  // namespace anvill
