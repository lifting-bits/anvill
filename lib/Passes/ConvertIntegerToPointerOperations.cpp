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

#include "Utils.h"

namespace anvill {

llvm::StringRef ConvertIntegerToPointerOperations::name(void) {
  return "PointerLifter";
}


namespace pats = llvm::PatternMatch;

llvm::PreservedAnalyses
ConvertIntegerToPointerOperations::run(llvm::Function &func,
                                       llvm::FunctionAnalysisManager &fam) {

  llvm::Value *index = nullptr;
  llvm::Value *base = nullptr;
  bool changed = false;
  for (auto &insn : llvm::instructions(func)) {


    if (auto ptr_ty = llvm::dyn_cast<llvm::PointerType>(insn.getType())) {
      auto elem_ty = ptr_ty->getElementType();
      auto elem_size_bits = elem_ty->getScalarSizeInBits();
      uint64_t shifting_left_by = 0;
      if (elem_ty->isIntegerTy()) {
        llvm::Instruction *insn_ptr = &insn;
        if (pats::match(insn_ptr,
                        pats::m_IntToPtr(pats::m_Add(
                            pats::m_Shl(pats::m_Value(index),
                                        pats::m_ConstantInt(shifting_left_by)),
                            pats::m_Value(base))))) {
          uint64_t byte_size = 1 << shifting_left_by;
          uint64_t shl_bit_isze = byte_size * 8;

          if (shl_bit_isze == elem_size_bits) {
            auto base_ptr = new llvm::IntToPtrInst(base, ptr_ty);
            std::vector<llvm::Value *> idxes = {index};
            ptr_ty->dump();
            base_ptr->dump();
            index->dump();
            auto gep = llvm::GetElementPtrInst::Create(ptr_ty, base_ptr, idxes);
            insn_ptr->replaceAllUsesWith(gep);
            changed = true;
          }
        }
      }
    }
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