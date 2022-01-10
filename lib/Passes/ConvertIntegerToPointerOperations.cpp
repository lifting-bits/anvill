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

llvm::StringRef ConvertIntegerToPointerOperations::name(void) {
  return "ConvertIntegerToPointerOperations";
}

namespace pats = llvm::PatternMatch;

llvm::PreservedAnalyses
ConvertIntegerToPointerOperations::run(llvm::Function &func,
                                       llvm::FunctionAnalysisManager &fam) {

  auto &dl = func.getParent()->getDataLayout();

  struct Match {
    llvm::Value *base;
    llvm::PointerType *ptr_ty;  // Needed for address space.
    llvm::Type *elem_ty;
    llvm::Value *index;
    llvm::IntToPtrInst *itp;
  };


  struct SignExtendMatch {
    uint64_t shift_left;
    uint64_t shift_right;
    llvm::Value *int_ptr;
    llvm::IntegerType *truncating_type;
    llvm::Value *ashr;
  };

  std::vector<Match> matches;

  std::vector<SignExtendMatch> sem_matches;
  for (auto &insn : llvm::instructions(func)) {
    SignExtendMatch sem;
    if (pats::match(
            &insn,
            pats::m_AShr(pats::m_Shl(pats::m_Value(sem.int_ptr),
                                     pats::m_ConstantInt(sem.shift_right)),
                         pats::m_ConstantInt(sem.shift_left)))) {
      if (sem.shift_left > sem.shift_right) {

        auto ty = sem.int_ptr->getType();
        if (auto int_ty = llvm::dyn_cast<llvm::IntegerType>(ty)) {
          auto orig_size = int_ty->getIntegerBitWidth();
          if (orig_size <= sem.shift_left) {
            continue;
          }
          sem.truncating_type = llvm::IntegerType::get(
              func.getContext(), orig_size - sem.shift_left);
          sem.ashr = &insn;
          sem_matches.push_back(sem);
        }
      }
    }
  }

  for (auto mat : sem_matches) {
    auto diff = mat.shift_left - mat.shift_right;
    llvm::TruncInst(mat.int_ptr, mat.truncating_type, "", mat.ashr);
  }

  for (auto &insn : llvm::instructions(func)) {
    Match match;
    match.itp = llvm::dyn_cast<llvm::IntToPtrInst>(&insn);
    if (match.itp) {
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
  }

  if (matches.empty()) {
    return llvm::PreservedAnalyses::all();
  }

  for (auto [base, ptr_ty, elem_ty, index, itp] : matches) {
    auto base_ptr = new llvm::IntToPtrInst(base, ptr_ty, "", itp);
    llvm::Value *idxes[] = {index};
    auto gep =
        llvm::GetElementPtrInst::Create(elem_ty, base_ptr, idxes, "", itp);
    itp->replaceAllUsesWith(gep);
  }

  return llvm::PreservedAnalyses::none();
}

void AddConvertIntegerToPointerOperations(llvm::FunctionPassManager &fpm) {
  fpm.addPass(ConvertIntegerToPointerOperations());
}
}  // namespace anvill