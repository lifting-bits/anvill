/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/ABI.h>
#include <anvill/Lifters.h>
#include <anvill/Passes/SplitStackFrameAtReturnAddress.h>
#include <anvill/Transforms.h>
#include <glog/logging.h>
#include <llvm/ADT/ArrayRef.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Intrinsics.h>
#include <remill/BC/Util.h>

#include <unordered_map>
#include <unordered_set>

#include "Utils.h"

namespace anvill {
namespace {

// Find the `alloca` instruction for the stack frame type.
static llvm::AllocaInst *FindStackFrameAlloca(llvm::Function &func) {
  for (auto &inst : func.getEntryBlock()) {
    auto alloca = llvm::dyn_cast<llvm::AllocaInst>(&inst);
    if (!alloca || !alloca->hasMetadata(kStackMetadata)) {
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
static std::vector<FixedOffsetUse>
FindFixedOffsetUses(llvm::AllocaInst *alloca) {

  const llvm::DataLayout &dl = alloca->getModule()->getDataLayout();
  const auto addr_size = dl.getIndexSizeInBits(0);

  std::vector<FixedOffsetUse> found;
  std::unordered_set<llvm::Use *> seen;
  std::vector<std::pair<llvm::Instruction *, llvm::APInt>> work_list;
  work_list.emplace_back(alloca, llvm::APInt(addr_size, 0u, true));

  auto add_to_found = [&found](llvm::Use &use, llvm::APInt offset) {
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
        default: break;
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
  auto &context = frame_alloca->getContext();
  auto stack_zero_md_id = context.getMDKindID(kAnvillStackZero);
  auto zero = frame_alloca->getMetadata(stack_zero_md_id);
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

  auto stack_offset_md_id =
      context.getMDKindID(options.stack_offset_metadata_name);

  auto zero_offset = zero_val->getSExtValue();
  auto create_metadata = [=, &context](llvm::Instruction *inst,
                                       int64_t offset) {
    int64_t disp = 0;
    if (options.stack_grows_down) {
      disp = zero_offset - offset;
    } else {
      disp = offset - zero_offset;
    }

    auto disp_val = llvm::ConstantInt::get(zero_val->getType(),
                                           static_cast<uint64_t>(disp), true);
    auto disp_md = llvm::ValueAsMetadata::get(disp_val);
    return llvm::MDNode::get(context, disp_md);
  };

  // Annotate the used instructions.
  for (const auto &use : uses) {
    auto inst = llvm::dyn_cast<llvm::Instruction>(use.use->get());
    if (!inst || inst->getMetadata(stack_offset_md_id)) {
      continue;  // Not an instruction, or already annotated.
    }

    auto offset = use.offset.getSExtValue();
    auto md = create_metadata(inst, offset);

    inst->setMetadata(stack_offset_md_id, md);
  }

  frame_alloca->setMetadata(stack_zero_md_id, nullptr);
}

// Find a `StoreInst` that looks like it puts the return address into the
// stack. Failure to find this means it likely stayed in registers.
static const FixedOffsetUse *
FindReturnAddressStore(const std::vector<FixedOffsetUse> &uses,
                       const StackFrameRecoveryOptions &options) {
  const FixedOffsetUse *found = nullptr;
  for (const auto &use : uses) {
    if (auto store = llvm::dyn_cast<llvm::StoreInst>(use.use->getUser())) {
      if (IsReturnAddress(store->getModule(), store->getValueOperand())) {
        if (!found) {
          found = &use;
        } else {
          auto prev_offset = found->offset.getSExtValue();
          auto curr_offset = use.offset.getSExtValue();

          if (options.stack_grows_down) {
            if (prev_offset > curr_offset) {
              LOG_IF(ERROR, prev_offset != curr_offset)
                  << "Found return address stored to two different offsets: "
                  << remill::LLVMThingToString(store) << " and "
                  << remill::LLVMThingToString(found->use->getUser())
                  << " in function " << store->getFunction()->getName().str()
                  << "; treating offset " << curr_offset
                  << " as return address location instead of " << prev_offset;
              found = &use;
            }
          } else {
            if (prev_offset < curr_offset) {
              LOG_IF(ERROR, prev_offset != curr_offset)
                  << "Found return address stored to two different offsets: "
                  << remill::LLVMThingToString(store) << " and "
                  << remill::LLVMThingToString(found->use->getUser())
                  << " in function " << store->getFunction()->getName().str()
                  << "; treating offset " << curr_offset
                  << " as return address location instead of " << prev_offset;
              found = &use;
            }
          }
        }
      }
    }
  }

  return found;
}

// Given a desired offset, figure out a pointer element type that will allow us
// to get to that offset, then produce a series of instructions that gets us
// to the offset, while trying to re-use previously constructed pointers.
static llvm::Instruction *DemandedOffset(
    llvm::IRBuilder<> &ir, llvm::Instruction *old_inst,
    std::unordered_map<uint64_t, llvm::Instruction *> &pointers,
    std::unordered_map<uint64_t, llvm::Instruction *> &computed_offsets,
    uint64_t desired_offset, uint64_t addr_size) {

  auto &inst = computed_offsets[desired_offset];
  if (inst) {
    return inst;
  }

  llvm::PointerType *ptr_type = nullptr;
  llvm::IntegerType *el_type = nullptr;
  auto &context = ir.getContext();
  uint64_t scale = 0;
  auto missing = desired_offset % addr_size;
  switch (missing) {
    case 7:
    case 5:
    case 3:
    case 1:
      el_type = llvm::Type::getInt8Ty(context);
      ptr_type = llvm::PointerType::get(context, 0);
      scale = 1;
      break;

    case 4:
      el_type = llvm::Type::getInt32Ty(context);
      ptr_type = llvm::PointerType::get(context, 0);
      scale = 4;
      break;

    case 6:
    case 2:
      el_type = llvm::Type::getInt16Ty(context);
      ptr_type = llvm::PointerType::get(context, 0);
      scale = 2;
      break;
    case 0: el_type = llvm::Type::getIntNTy(context, addr_size * 8u); break;
    default: LOG(FATAL) << "Unsupported address size: " << addr_size; break;
  }

  auto base = pointers[addr_size];

  if (ptr_type) {
    auto &new_base = pointers[scale];
    if (!new_base) {
      new_base = llvm::dyn_cast<llvm::Instruction>(
          ir.CreateBitOrPointerCast(base, ptr_type));
      CopyMetadataTo(base, new_base);
    }
    base = new_base;
  } else {
    scale = addr_size;
    ptr_type = llvm::PointerType::get(context, 0);
  }

  inst = llvm::dyn_cast<llvm::Instruction>(
      ir.CreateGEP(el_type, base, ir.getInt32(desired_offset / scale)));
  CopyMetadataTo(old_inst, inst);

  return inst;
}

static void SubstituteUse(
    llvm::IRBuilder<> &ir, llvm::Use *use, uint64_t offset, uint64_t addr_size,
    std::unordered_map<uint64_t, llvm::Instruction *> &pointers,
    std::unordered_map<uint64_t, llvm::Instruction *> &computed_offsets,
    std::unordered_map<llvm::Instruction *, llvm::Value *> &to_replace) {
  auto use_inst = llvm::dyn_cast<llvm::Instruction>(use->get());
  auto user_inst = llvm::dyn_cast<llvm::Instruction>(use->getUser());
  CHECK_NOTNULL(use_inst);
  CHECK_NOTNULL(user_inst);  // Not sure. Metadata, perhaps?

  llvm::Instruction *const ret = DemandedOffset(
      ir, use_inst, pointers, computed_offsets, offset, addr_size);
  CHECK_NOTNULL(ret);

  CopyMetadataTo(use_inst, ret);

  switch (user_inst->getOpcode()) {

    // Convert a `ptrtoint` into a `ptrtoint`.
    case llvm::Instruction::PtrToInt:
      if (!to_replace.count(user_inst)) {
        auto pti = ir.CreatePtrToInt(ret, user_inst->getType());
        CopyMetadataTo(user_inst, pti);
        to_replace.emplace(user_inst, pti);
      }
      break;

    // Integral arithmetic/operations on pointers; we need to cast to an
    // integer.
    case llvm::Instruction::Add:
    case llvm::Instruction::Sub:
    case llvm::Instruction::Mul:
    case llvm::Instruction::SDiv:
    case llvm::Instruction::UDiv:
    case llvm::Instruction::ZExt:
    case llvm::Instruction::SExt:
    case llvm::Instruction::Trunc:
    case llvm::Instruction::Or:
    case llvm::Instruction::Xor:
    case llvm::Instruction::And: {
      auto pti = ir.CreatePtrToInt(ret, use_inst->getType());
      CopyMetadataTo(use_inst, pti);
      use->set(pti);
      break;
    }

    // These might operate on either pointers or integers.
    case llvm::Instruction::ICmp:
    case llvm::Instruction::PHI:
    case llvm::Instruction::Select:
    default: {
      auto ty = use_inst->getType();
      if (ty->isIntegerTy()) {
        auto pti = ir.CreatePtrToInt(ret, ty);
        CopyMetadataTo(use_inst, pti);
        use->set(pti);
      } else {
        auto bc = ir.CreateBitOrPointerCast(ret, ty);
        CopyMetadataTo(use_inst, bc);
        use->set(bc);
      }
      break;
    }

    // Convert an `inttoptr` into a pointer-to-pointer `bitcast`. If it's
    // already a `bitcast`, then also convert it to a `bitcast`.
    case llvm::Instruction::IntToPtr:
    case llvm::Instruction::BitCast:
      if (!to_replace.count(user_inst)) {
        auto bc = ir.CreateBitOrPointerCast(ret, user_inst->getType());
        CopyMetadataTo(user_inst, bc);
        to_replace.emplace(user_inst, bc);
      }
      break;

    // If the user is a `load`, then replace its use of the pointer.
    case llvm::Instruction::Load: {
      auto li = llvm::dyn_cast<llvm::LoadInst>(user_inst);
      auto pty =
          llvm::PointerType::get(ir.getContext(), li->getPointerAddressSpace());
      auto bc = ir.CreateBitOrPointerCast(ret, pty);
      CopyMetadataTo(use_inst, bc);
      use->set(bc);
      break;
    }

    // If the user is a `store`, then replace its use of the pointer.
    case llvm::Instruction::Store: {
      auto si = llvm::dyn_cast<llvm::StoreInst>(user_inst);
      auto ty = si->getValueOperand()->getType();

      // Operating on the value being stored.
      if (use == &(si->getOperandUse(0u))) {
        if (ty->isIntegerTy()) {
          auto pti = ir.CreatePtrToInt(ret, ty);
          CopyMetadataTo(use_inst, pti);
          use->set(pti);
        } else {
          auto bc = ir.CreateBitOrPointerCast(ret, ty);
          CopyMetadataTo(use_inst, bc);
          use->set(bc);
        }

        // Operating on the pointer.
      } else {
        auto pty = llvm::PointerType::get(ir.getContext(),
                                          si->getPointerAddressSpace());
        auto bc = ir.CreateBitOrPointerCast(ret, pty);
        CopyMetadataTo(use_inst, bc);
        use->set(bc);
      }
      break;
    }

    case llvm::Instruction::GetElementPtr: {
      auto gep = llvm::dyn_cast<llvm::GetElementPtrInst>(user_inst);

      // This easy; the GEP has all constant indices to we can schedule it
      // for replacement.
      if (gep->hasAllConstantIndices()) {
        if (!to_replace.count(user_inst)) {
          auto bc = ir.CreateBitOrPointerCast(ret, user_inst->getType());
          CopyMetadataTo(user_inst, bc);
          to_replace.emplace(user_inst, bc);
        }

        // This is trickier; we need to form a new GEP or something like it.
      } else {
        llvm::SmallVector<const llvm::Value *, 4u> const_indices_c;
        llvm::SmallVector<llvm::Value *, 4u> const_indices;
        llvm::SmallVector<llvm::Value *, 4u> var_indices;
        for (llvm::Use &index : gep->indices()) {
          if (auto ci = llvm::dyn_cast<llvm::ConstantInt>(index.get())) {
            if (var_indices.empty()) {
              const_indices.emplace_back(ci);
              const_indices_c.emplace_back(ci);
            } else {
              var_indices.emplace_back(ci);
            }
          } else {
            var_indices.emplace_back(index.get());
          }
        }

        CHECK(!var_indices.empty());

        auto addr_space = gep->getPointerAddressSpace();

        // This is the easy case, because we can replace the use with
        // something that was constant calculated.
        if (const_indices.empty()) {
          auto pty = llvm::PointerType::get(ir.getContext(), addr_space);
          auto bc = ir.CreateBitOrPointerCast(ret, pty);
          CopyMetadataTo(use_inst, bc);
          use->set(bc);

          // This is the hard case, because we need to invent a new GEP.
        } else if (!to_replace.count(user_inst)) {
          llvm::APInt sub_offset(addr_size * 8u, 0u);
          auto source_ty = gep->getSourceElementType();
          auto &dl = user_inst->getModule()->getDataLayout();
          CHECK(llvm::GEPOperator::accumulateConstantOffset(
              source_ty, const_indices_c, dl, sub_offset));

          auto effective_sub_offset = static_cast<uint64_t>(
              static_cast<int64_t>(offset) + sub_offset.getSExtValue());
          llvm::Instruction *const sub_ret =
              DemandedOffset(ir, use_inst, pointers, computed_offsets,
                             effective_sub_offset, addr_size);

          CHECK_NOTNULL(sub_ret);
          CopyMetadataTo(use_inst, sub_ret);

          auto sub_ret_ty =
              llvm::GetElementPtrInst::getIndexedType(source_ty, const_indices);
          auto sub_ret_pty =
              llvm::PointerType::get(ir.getContext(), addr_space);

          auto bc = ir.CreateBitOrPointerCast(ret, sub_ret_pty);
          CopyMetadataTo(user_inst, bc);

          auto new_gep = ir.CreateGEP(sub_ret_ty, bc, var_indices);
          CopyMetadataTo(user_inst, new_gep);

          to_replace.emplace(user_inst, new_gep);
        }
      }
      break;
    }
  }
}

static void SplitStackFrameAround(llvm::AllocaInst *frame_alloca,
                                  std::vector<FixedOffsetUse> uses,
                                  const StackFrameRecoveryOptions &options) {

  llvm::LLVMContext &context = frame_alloca->getContext();
  llvm::Module *const module = frame_alloca->getModule();
  const llvm::DataLayout &dl = module->getDataLayout();
  const auto addr_size = dl.getPointerSize(0);
  const auto addr_size_bits = dl.getPointerSizeInBits(0);
  llvm::IntegerType *const addr_type =
      llvm::Type::getIntNTy(context, addr_size * 8u);

  // If we don't find a return address store, then we'll still split at zero.
  //
  // TODO(pag): We could in theory have a function in something like aarch64
  //            that doesn't spill its return address, but does save it to
  //            the stack in the interior of a structure which then gets passed
  //            along (kind of like what `__libc_dlopen_mode` does). Perhaps
  //            consider architecture-specific "appropriate" split locations
  //            in the presence of a non-`nullptr` `store_use`, which should
  //            probably often be 0.
  const FixedOffsetUse *store_use = FindReturnAddressStore(uses, options);

  uint64_t offset_of_ra = 0;
  uint64_t end_of_ra = 1;
  if (store_use) {
    offset_of_ra = store_use->offset.getZExtValue();
    end_of_ra = offset_of_ra + addr_size;

    // Log the above scenario out in case it comes up.
    if (auto user_inst =
            llvm::dyn_cast<llvm::Instruction>(store_use->use->getUser());
        user_inst && offset_of_ra != 0) {

      LOG(INFO) << "Offset of return address storage location in function "
                << frame_alloca->getFunction()->getName().str() << " is "
                << offset_of_ra << ": " << remill::LLVMThingToString(user_inst)
                << " in block " << user_inst->getParent()->getName().str();
    }
  }

  std::vector<std::pair<llvm::Use *, uint64_t>> above;
  std::vector<std::pair<llvm::Use *, uint64_t>> at;
  std::vector<std::pair<llvm::Use *, uint64_t>> below;

  // NOTE(pag): This assumes that the base uses don't cross over the return
  //            address.
  for (FixedOffsetUse &use : uses) {
    DCHECK_LE(0, use.offset.getSExtValue());
    const auto use_offset = use.offset.getZExtValue();

    if (use_offset < offset_of_ra) {
      above.emplace_back(use.use, use_offset);

    } else if (offset_of_ra <= use_offset && use_offset < end_of_ra) {
      at.emplace_back(use.use, use_offset - offset_of_ra);

    } else {
      below.emplace_back(use.use, use_offset - end_of_ra);
    }
  }

  llvm::IRBuilder<> ir(frame_alloca);
  llvm::AllocaInst *sub_frame = nullptr;

  std::unordered_map<uint64_t, llvm::Instruction *> pointers;
  std::unordered_map<uint64_t, llvm::Instruction *> computed_offsets;
  std::unordered_map<llvm::Instruction *, llvm::Value *> to_replace;

  auto make_subframe =
      [&](std::vector<std::pair<llvm::Use *, uint64_t>> use_offsets,
          const char *down_name, const char *up_name, uint64_t num_slots) {
        auto num_slots_val = ir.getIntN(addr_size_bits, num_slots);
        if (options.stack_grows_down) {
          sub_frame = ir.CreateAlloca(addr_type, 0u, num_slots_val, down_name);
        } else {
          sub_frame = ir.CreateAlloca(addr_type, 0u, num_slots_val, up_name);
        }

        pointers.clear();
        computed_offsets.clear();

        pointers.emplace(addr_size, sub_frame);
        computed_offsets.emplace(0, sub_frame);

        CopyMetadataTo(frame_alloca, sub_frame);

        for (auto [use, offset] : use_offsets) {
          SubstituteUse(ir, use, offset, addr_size, pointers, computed_offsets,
                        to_replace);
        }
      };

  if (!above.empty()) {
    auto num_slots = (offset_of_ra + (addr_size - 1u)) / addr_size;
    make_subframe(std::move(above), "parameters", "locals", num_slots);
  }

  if (!below.empty()) {
    auto frame_size =
        dl.getTypeAllocSize(frame_alloca->getAllocatedType()).getKnownMinSize();
    auto num_slots = ((frame_size - end_of_ra) + (addr_size - 1u)) / addr_size;
    make_subframe(std::move(below), "locals", "parameters", num_slots);
  }

  if (!at.empty()) {
    make_subframe(std::move(at), "return_address_loc", "return_address_loc", 1);
  }

  for (auto [old_val, new_val] : to_replace) {
    old_val->dropAllReferences();
    old_val->replaceAllUsesWith(new_val);
    old_val->eraseFromParent();
  }
}

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

  SplitStackFrameAround(frame_alloca, std::move(uses), options);

  return llvm::PreservedAnalyses::none();
}

llvm::StringRef SplitStackFrameAtReturnAddress::name(void) {
  return llvm::StringRef("SplitStackFrameAtReturnAddress");
}

void AddSplitStackFrameAtReturnAddress(
    llvm::FunctionPassManager &fpm, const StackFrameRecoveryOptions &options) {
  fpm.addPass(SplitStackFrameAtReturnAddress(options));
}

}  // namespace anvill
