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

#include <vector>

#include "Utils.h"

namespace anvill {
namespace {

// Identify `(ashr (shl V, A), B)` and try to convert to
//
//        V_short = trunc V to iA
//        V_signed = sext V_short
//        res = shl V_signed, A - B
static bool FoldAshrSlh(llvm::Function &func) {
  struct SignExtendMatch {
    uint64_t shift_left;
    uint64_t shift_right;
    llvm::IntegerType *full_type;
    llvm::Value *int_ptr;
    llvm::Instruction *ashr;
  };

  auto &context = func.getContext();

  std::vector<SignExtendMatch> matches;
  for (auto &insn : llvm::instructions(func)) {
    namespace pats = llvm::PatternMatch;

    SignExtendMatch sem;
    if (!pats::match(
            &insn,
            pats::m_AShr(pats::m_Shl(pats::m_Value(sem.int_ptr),
                                     pats::m_ConstantInt(sem.shift_right)),
                         pats::m_ConstantInt(sem.shift_left)))) {
      continue;
    }

    sem.full_type = llvm::dyn_cast<llvm::IntegerType>(sem.int_ptr->getType());
    if (!sem.full_type) {
      continue;
    }

    // Make sure that we're a shift by half the size of the integer type. When
    // the shift right is then smaller than the shl, it narrows us to looking
    // at only the pattern of shifting a (narrower) signed value left, that
    // happens to be stored in a wider value.
    auto orig_size = sem.full_type->getIntegerBitWidth();
    if (sem.shift_left > sem.shift_right &&
        ((sem.shift_left * 2u) == orig_size)) {

      sem.ashr = &insn;
      matches.push_back(sem);
    }
  }

  for (auto mat : matches) {
    auto new_shl_amount = mat.shift_left - mat.shift_right;

    auto half_type = llvm::IntegerType::get(
        context, mat.shift_left);

    auto trunc = new llvm::TruncInst(mat.int_ptr, half_type, "", mat.ashr);
    auto sext = new llvm::SExtInst(trunc, mat.full_type, "", mat.ashr);
    auto shl = llvm::BinaryOperator::Create(
        llvm::BinaryOperator::BinaryOps::Shl,
        sext,
        llvm::ConstantInt::get(mat.full_type, new_shl_amount),
        "",
        mat.ashr);

    anvill::CopyMetadataTo(mat.int_ptr, trunc);
    anvill::CopyMetadataTo(mat.ashr, sext);
    anvill::CopyMetadataTo(mat.ashr->getOperand(0u), shl);
    mat.ashr->replaceAllUsesWith(shl);
    mat.ashr->eraseFromParent();
  }

  return !matches.empty();
}

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

  for (auto &insn : llvm::instructions(func)) {
    namespace pats = llvm::PatternMatch;

    ScaledLoadMatch match;
    match.itp = llvm::dyn_cast<llvm::IntToPtrInst>(&insn);
    if (!match.itp) {
      continue;
    }
    match.ptr_ty = llvm::dyn_cast<llvm::PointerType>(match.itp->getType());
    match.elem_ty = match.ptr_ty->getElementType();


    if (!match.elem_ty->isSized()) {
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

}  // namespace

llvm::StringRef ConvertIntegerToPointerOperations::name(void) {
  return "ConvertIntegerToPointerOperations";
}


llvm::PreservedAnalyses
ConvertIntegerToPointerOperations::run(llvm::Function &func,
                                       llvm::FunctionAnalysisManager &fam) {

  auto changed = false;
  if (FoldAshrSlh(func)) {
    changed = true;
  }

  if (FoldBasePlusScaledIndex(func)) {
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
