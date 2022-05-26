/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Passes/ConvertIntegerToPointerOperations.h>
#include <anvill/Transforms.h>
#include <llvm/IR/PatternMatch.h>
#include <llvm/IR/Verifier.h>

#include <algorithm>
#include <cassert>
#include <unordered_map>
#include <vector>

#include "Utils.h"

namespace anvill {
namespace {

// Look for `(inttoptr (add B (shl I S)))` and convert it into:
//
//    B_ptr = intoptr B to X*
//    Res = getelementptr B_ptr, I
static bool FoldBasePlusScaledIndex(llvm::Function &func) {
  auto &dl = func.getParent()->getDataLayout();
  struct ScaledLoadMatch {
    llvm::Value *base;
    llvm::PointerType *ptr_ty;  // Needed for address space.
    llvm::Type *elem_ty;
    llvm::Value *index;
    llvm::IntToPtrInst *itp;
  };

  std::vector<ScaledLoadMatch> matches;
  llvm::SmallPtrSet<llvm::Type *, 16> sized_types;

  for (auto &insn : llvm::instructions(func)) {
    namespace pats = llvm::PatternMatch;

    ScaledLoadMatch match;
    match.itp = llvm::dyn_cast<llvm::IntToPtrInst>(&insn);
    if (!match.itp) {
      continue;
    }
    match.ptr_ty = llvm::dyn_cast<llvm::PointerType>(match.itp->getType());
    match.elem_ty = match.ptr_ty->getElementType();

    if (!match.elem_ty->isSized(&sized_types)) {
      continue;
    }

    auto elem_size = dl.getTypeSizeInBits(match.elem_ty);
    if (elem_size.isScalable()) {
      continue;
    }

    uint64_t shifting_left_by = 0;
    uint64_t elem_size_bits = elem_size.getFixedSize();

    if (!pats::match(match.itp,
                     pats::m_IntToPtr(pats::m_Add(
                         pats::m_Shl(pats::m_Value(match.index),
                                     pats::m_ConstantInt(shifting_left_by)),
                         pats::m_Value(match.base))))) {
      continue;
    }

    uint64_t byte_size = 1ull << shifting_left_by;
    uint64_t shl_bit_size = byte_size * 8;

    if (shl_bit_size == elem_size_bits) {
      matches.emplace_back(std::move(match));
    }
  }

  for (auto [base, ptr_ty, elem_ty, index, itp] : matches) {
    auto base_ptr = new llvm::IntToPtrInst(base, ptr_ty, "", itp);
    llvm::Value *idxes[] = {index};
    auto gep =
        llvm::GetElementPtrInst::Create(elem_ty, base_ptr, idxes, "", itp);

    anvill::CopyMetadataTo(itp, base_ptr);
    anvill::CopyMetadataTo(itp, gep);
    itp->replaceAllUsesWith(gep);
    itp->eraseFromParent();
  }

  return !matches.empty();
}

// Convert `(inttoptr (load X))` into `(load (bitcast X))`.
//
// This transform has to be more careful because we need to synthesize
// replacement loads, but we don't want to introduce more loads than were
// originally in the program.
static bool IntToPtrOnLoadToLoadOfPointer(llvm::Function &func) {
  auto &dl = func.getParent()->getDataLayout();

  struct LoadPtrMatch {
    llvm::IntToPtrInst *itp;
    llvm::LoadInst *load;
  };

  std::vector<LoadPtrMatch> matches;

  for (llvm::Instruction &insn : llvm::instructions(func)) {

    LoadPtrMatch match;
    match.itp = llvm::dyn_cast<llvm::IntToPtrInst>(&insn);
    if (!match.itp) {
      continue;
    }

    match.load = llvm::dyn_cast<llvm::LoadInst>(match.itp->getOperand(0u));
    if (!match.load) {
      continue;
    }

    // Make sure that the loaded integral type is the same size as
    // the casted pointer type, so that if we load a pointer-to-pointer,
    // then it will be a same-sized load.
    if (dl.getTypeStoreSize(match.itp->getType()) !=
        dl.getTypeStoreSize(match.load->getType())) {
      continue;
    }

    matches.emplace_back(std::move(match));
  }

  std::unordered_map<llvm::LoadInst *, llvm::LoadInst *> new_loads;

  auto changed = false;
  for (auto [itp, load] : matches) {

    // We want to turn the result type of the load into a pointer, which means
    // the load is loading a pointer-to-pointer.
    auto ptr_ptr_type =
        llvm::PointerType::get(func.getContext(), load->getPointerAddressSpace());

    // Drill down a bit further on the actual loaded operand.
    auto lo = load->getOperand(0)->stripPointerCasts();
    auto lo_type = lo->getType();

    // Only handle integers and pointers.
    if (!llvm::isa<llvm::IntegerType>(lo_type) &&
        !llvm::isa<llvm::PointerType>(lo_type)) {
      continue;
    }

    llvm::LoadInst *&new_load = new_loads[load];
    if (!new_load) {
      llvm::Instruction *new_base = nullptr;

      // It was a load of an integer that was casted to pointer (then stripped).
      if (llvm::isa<llvm::IntegerType>(lo_type)) {
        new_base = new llvm::IntToPtrInst(lo, ptr_ptr_type, "", load);

        // It was a load of a pointer.
      } else if (llvm::isa<llvm::PointerType>(lo_type)) {
        new_base = new llvm::BitCastInst(lo, ptr_ptr_type, "", load);
      }

      new_load = new llvm::LoadInst(itp->getType(), new_base, "", load);
      new_load->setAtomic(load->getOrdering(), load->getSyncScopeID());
      new_load->setAlignment(load->getAlign());

      anvill::CopyMetadataTo(load, new_base);
      anvill::CopyMetadataTo(load, new_load);

      itp->dropAllReferences();
      itp->replaceAllUsesWith(new_load);
      itp->eraseFromParent();

      // Already found and types match, use the previously created new version.
    } else if (new_load->getType() == itp->getType()) {
      itp->dropAllReferences();
      itp->replaceAllUsesWith(new_load);
      itp->eraseFromParent();

      // Types don't match, make a bitcast.
    } else {
      auto bc = new llvm::BitCastInst(new_load, itp->getType(), "", itp);
      anvill::CopyMetadataTo(itp, bc);

      itp->dropAllReferences();
      itp->replaceAllUsesWith(bc);
      itp->eraseFromParent();
    }

    changed = true;
  }

  // Remove any remaining uses of the old load. If there are old uses, then they
  // must be operating on integers, so we can cast our new load (which loads
  // a pointer) to an integer.
  for (auto [old_load, new_load] : new_loads) {
    if (!old_load->use_empty()) {
      auto new_pti =
          new llvm::PtrToIntInst(new_load, old_load->getType(), "", old_load);
      old_load->replaceAllUsesWith(new_pti);
      anvill::CopyMetadataTo(old_load, new_load);
    }

    old_load->eraseFromParent();
  }

  return changed;
}

// Look for `(inttoptr (add X, N), T*)` where `N` evenly divides `sizeof(T)`,
// and convert to `(getelementptr (inttoptr X, T *), (N / sizeof(T)))`.
static bool IntToPtrOnAddToGetElementPtr(llvm::Function &func) {
  struct LoadPtrMatch {
    llvm::IntToPtrInst *itp;
    llvm::BinaryOperator *add;
    llvm::ConstantInt *index;
  };

  auto &dl = func.getParent()->getDataLayout();

  std::vector<LoadPtrMatch> matches;

  llvm::SmallPtrSet<llvm::Type *, 16> sized_types;

  for (llvm::Instruction &insn : llvm::instructions(func)) {

    LoadPtrMatch match;
    match.itp = llvm::dyn_cast<llvm::IntToPtrInst>(&insn);
    if (!match.itp) {
      continue;
    }

    auto ptr_type = llvm::dyn_cast<llvm::PointerType>(match.itp->getType());
    if (!ptr_type) {
      assert(false);
      continue;
    }

    // If the pointer element type isn't sized, then we can't index into it.
    auto ptr_elem_type = ptr_type->getElementType();
    if (!ptr_elem_type->isSized(&sized_types)) {
      continue;
    }

    auto elem_size = dl.getTypeAllocSize(ptr_elem_type);
    if (elem_size.isScalable()) {
      continue;
    }

    match.add = llvm::dyn_cast<llvm::BinaryOperator>(match.itp->getOperand(0u));

    if (!match.add) {
      continue;
    }

    auto is_add = match.add->getOpcode() == llvm::Instruction::Add;
    auto is_sub = match.add->getOpcode() == llvm::Instruction::Sub;
    if (!is_add && !is_sub) {
      continue;
    }

    auto rhs = llvm::dyn_cast<llvm::ConstantInt>(match.add->getOperand(1u));
    if (!rhs) {
      continue;
    }

    auto ci_type = rhs->getType();
    switch (ci_type->getIntegerBitWidth()) {
      case 8:
      case 16:
      case 32:
      case 64: break;
      default: continue;
    }

    // Normalize subtracts into additions, because `getelementptr` supports
    // negative indices.
    if (is_sub) {
      rhs = llvm::ConstantInt::get(ci_type,
                                   static_cast<uint64_t>(-rhs->getSExtValue()),
                                   true /* is signed */);
    }

    int64_t positive_ci = 0;
    int64_t sign_multiple = 1;
    bool is_signed = false;
    if (rhs->isNegative()) {
      is_signed = true;
      sign_multiple = -1;
      positive_ci = -rhs->getSExtValue();
    } else {
      positive_ci = static_cast<int64_t>(rhs->getZExtValue());
    }

    // Make sure the integer being added evenly divides the pointer element
    // size.
    auto actual_elem_size = static_cast<int64_t>(elem_size.getFixedSize());
    if (positive_ci % actual_elem_size) {
      continue;
    }

    // Compute the new index to fill into the `getelementptr`.
    match.index = llvm::ConstantInt::get(
        ci_type, static_cast<uint64_t>(positive_ci * sign_multiple), is_signed);

    matches.emplace_back(std::move(match));
  }

  auto changed = false;
  for (auto [itp, add, index] : matches) {
    auto lhs = add->getOperand(0)->stripPointerCasts();
    auto lhs_type = lhs->getType();
    auto ptr_type = llvm::dyn_cast<llvm::PointerType>(itp->getType());

    // Figure out a reasonable insertion point.
    //
    // NOTE(pag): Every block contains a terminator.
    // NOTE(ian): We insert infront of the ptr cast so that the operand dominates us and we dont insert in the middle of phis.
    llvm::Instruction *ipoint = itp;

    llvm::Value *lhs_ptr = nullptr;
    if (llvm::isa<llvm::PointerType>(lhs_type)) {
      if (lhs_type != ptr_type) {
        lhs_ptr = new llvm::BitCastInst(lhs, ptr_type, "", ipoint);

      } else {
        lhs_ptr = lhs;
      }
    } else if (llvm::isa<llvm::IntegerType>(lhs_type)) {
      lhs_ptr = new llvm::IntToPtrInst(lhs, ptr_type, "", ipoint);

    } else {
      continue;
    }

    llvm::Value *indexes[] = {index};
    auto gep = llvm::GetElementPtrInst::Create(
        lhs_ptr->getType(), lhs_ptr, indexes, "", ipoint);

    anvill::CopyMetadataTo(itp, lhs_ptr);
    anvill::CopyMetadataTo(itp, gep);
    itp->dropAllReferences();
    itp->replaceAllUsesWith(gep);
    itp->eraseFromParent();

    if (add->use_empty()) {
      add->dropAllReferences();
      add->eraseFromParent();
    }

    changed = true;
  }

  return changed;
}

}  // namespace

llvm::StringRef ConvertIntegerToPointerOperations::name(void) {
  return "ConvertIntegerToPointerOperations";
}


llvm::PreservedAnalyses
ConvertIntegerToPointerOperations::run(llvm::Function &func,
                                       llvm::FunctionAnalysisManager &fam) {

  auto changed = false;
  if (FoldBasePlusScaledIndex(func)) {
    changed = true;
  }

  if (IntToPtrOnLoadToLoadOfPointer(func)) {
    changed = true;
  }

  if (IntToPtrOnAddToGetElementPtr(func)) {
    changed = true;
  }

  if (changed) {
    return llvm::PreservedAnalyses::none();
  } else {
    return llvm::PreservedAnalyses::all();
  }
}

void AddConvertIntegerToPointerOperations(llvm::FunctionPassManager &fpm) {
  fpm.addPass(ConvertIntegerToPointerOperations());
}
}  // namespace anvill
