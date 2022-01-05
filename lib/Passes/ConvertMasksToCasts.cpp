/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Passes/ConvertMasksToCasts.h>

#include <anvill/ABI.h>
#include <anvill/Utils.h>
#include <glog/logging.h>
#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PatternMatch.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include <optional>
#include <tuple>
#include <unordered_set>
#include <vector>

#include "Utils.h"

namespace anvill {

llvm::PreservedAnalyses
ConvertMasksToCasts::run(llvm::Function &func,
                         llvm::FunctionAnalysisManager &AM) {
  using namespace llvm::PatternMatch;

  std::vector<std::tuple<llvm::Instruction *, unsigned, llvm::Type *>>
      trunc_zexts;

  std::vector<std::pair<llvm::Instruction *, llvm::Type *>> shl_ashrs;

  std::vector<std::pair<llvm::Instruction *, llvm::APInt>> shl_adds;

  std::unordered_set<llvm::Instruction *> to_remove;

  auto &context = func.getContext();
  for (auto &inst : llvm::instructions(func)) {
    llvm::Value *val_to_mask = nullptr;
    llvm::ConstantInt *mask = nullptr;

    llvm::Value *val_to_sext = nullptr;
    llvm::ConstantInt *shl_amount = nullptr;
    llvm::ConstantInt *ashr_amount = nullptr;

    llvm::Value *val_to_add = nullptr;
    llvm::ConstantInt *added_val = nullptr;

    auto do_mask = [&] (unsigned op) {
      auto &apv = mask->getValue();
      const auto real_width = apv.getBitWidth();
      const auto effective_width = apv.getActiveBits();
      if ((effective_width * 2u) == real_width &&
          (~apv).countTrailingZeros() == effective_width) {
        trunc_zexts.emplace_back(
            &inst, op, llvm::Type::getIntNTy(context, effective_width));
      }
    };

    // Go find cases of `and iN, iN (~0 >> N)`.
    if (match(&inst, m_And(m_Value(val_to_mask), m_ConstantInt(mask)))) {
      do_mask(0u);

    } else if (match(&inst, m_And(m_ConstantInt(mask), m_Value(val_to_mask)))) {
      do_mask(1u);

    // Go find the cases of `((intN_t) (val << (N/2))) >> (N/2)`.
    } else if (match(&inst, m_AShr(m_Shl(m_Value(val_to_sext),
                                         m_ConstantInt(shl_amount)),
                                   m_ConstantInt(ashr_amount))) &&
               shl_amount == ashr_amount) {
      auto target_type = llvm::dyn_cast<llvm::IntegerType>(inst.getType());
      switch (auto target_size = target_type->getBitWidth()) {
        case 8: case 16: case 32: case 64: case 128:
          shl_ashrs.emplace_back(
              &inst, llvm::Type::getIntNTy(context, target_size / 2u));
          break;
        default:
          break;
      }

    // Go find cases of `(add (shl val N) (M << N))`.
    } else if (match(&inst, m_Add(m_Shl(m_Value(val_to_add),
                                        m_ConstantInt(shl_amount)),
                                  m_ConstantInt(added_val)))) {
      switch (auto num_zeroes = shl_amount->getZExtValue()) {
        case 8: case 16: case 32: case 64: case 128: {
          const llvm::APInt &added_ap = added_val->getValue();
          if (added_ap.countTrailingZeros() >= num_zeroes) {
            shl_adds.emplace_back(
                &inst, added_ap.lshr(static_cast<unsigned>(num_zeroes)));
          }
          break;
        }
        default:
          break;
      }
    }
  }

  bool changed = false;
  int replaced_items = 0;

  llvm::IRBuilder<> ir(context);

  // Replace `(and val mask)` with `(zext (trunc val))`.
  for (auto [inst, op_num, half_type] : trunc_zexts) {
    ir.SetInsertPoint(inst);

    // Work in terms of `op_num` to observe results of RAUW across loop
    // iterations.
    auto val_to_mask = inst->getOperand(op_num);

    auto down_casted_val = ir.CreateTrunc(val_to_mask, half_type);
    auto up_casted_val = ir.CreateZExt(down_casted_val, inst->getType());
    CopyMetadataTo(inst, down_casted_val);
    CopyMetadataTo(inst, up_casted_val);
    inst->replaceAllUsesWith(up_casted_val);
    inst->eraseFromParent();
    ++replaced_items;
    changed = true;
  }


  // Replace `(add (shl val N) (M << N))` with `(shl (add val M) N)`.
  for (auto [inst, addend] : shl_adds) {
    ir.SetInsertPoint(inst);

    // Go pull out the value to add again, just in case uses of RAUW
    // have changed things.
    llvm::Instruction *shl = nullptr;
    llvm::Value *val_to_add = nullptr;
    llvm::ConstantInt *shl_val = nullptr;
    if (!match(inst, m_Add(m_Instruction(shl), m_ConstantInt())) ||
        !match(shl, m_Shl(m_Value(val_to_add), m_ConstantInt(shl_val)))) {
      continue;
    }

    auto new_val_to_add = llvm::ConstantInt::get(val_to_add->getType(), addend);
    auto new_added_base = ir.CreateAdd(val_to_add, new_val_to_add);
    auto new_shl = ir.CreateShl(new_added_base, shl_val);
    CopyMetadataTo(inst, new_added_base);
    CopyMetadataTo(inst, new_shl);

    inst->replaceAllUsesWith(new_shl);
    inst->eraseFromParent();

    to_remove.insert(shl);
  }

  // Replace `(ashr (shl ...) ...)` with `(sext (trunc ...))`.
  for (auto [inst, half_type] : shl_ashrs) {
    ir.SetInsertPoint(inst);

    // Go pull out the value to sign extend again, just in case uses of RAUW
    // have changed things.
    llvm::Value *val_to_sext = nullptr;
    llvm::Instruction *shl = nullptr;
    if (!match(inst, m_AShr(m_Instruction(shl), m_ConstantInt())) ||
        !match(shl, m_Shl(m_Value(val_to_sext), m_ConstantInt()))) {
      continue;
    }

    auto down_casted_val = ir.CreateTrunc(val_to_sext, half_type);
    auto up_casted_val = ir.CreateSExt(down_casted_val, inst->getType());
    CopyMetadataTo(inst, down_casted_val);
    CopyMetadataTo(inst, up_casted_val);
    inst->replaceAllUsesWith(up_casted_val);
    inst->eraseFromParent();

    to_remove.insert(shl);

    ++replaced_items;
    changed = true;
  }

  // Get rid of any `shl` instructions.
  for (auto inst : to_remove) {
    if (!inst->hasNUsesOrMore(1u)) {
      inst->eraseFromParent();
    }
  }

  return ConvertBoolToPreserved(changed);
}


llvm::StringRef ConvertMasksToCasts::name(void) {
  return llvm::StringRef("ConvertMasksToCasts");
}

// Convert bit masks on wide integer types into combinations of truncations
// and zero-extensions. Also, look for shift lefts followed by arithmetic shift
// rights and convert them into truncations followed by sign-extensions.
void AddConvertMasksToCasts(llvm::FunctionPassManager &fpm) {
  fpm.addPass(ConvertMasksToCasts());
}

}  // namespace anvill
