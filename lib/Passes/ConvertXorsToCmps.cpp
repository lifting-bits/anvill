/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/ABI.h>
#include <anvill/Passes/ConvertXorsToCmps.h>
#include <glog/logging.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>
#include <remill/BC/Util.h>

#include <optional>
#include <tuple>
#include <vector>

#include "Utils.h"

namespace anvill {
namespace {

static std::optional<std::tuple<llvm::Value *, llvm::ConstantInt *>>
getVariableOperands(llvm::BinaryOperator *op) {

  auto lhs_c = llvm::dyn_cast<llvm::ConstantInt>(op->getOperand(0));
  auto lhs_val = llvm::dyn_cast<llvm::Value>(op->getOperand(0));

  auto rhs_c = llvm::dyn_cast<llvm::ConstantInt>(op->getOperand(1));
  auto rhs_val = llvm::dyn_cast<llvm::Value>(op->getOperand(1));

  // check for an operation between a constant and a variable
  // and return the variable as the left op, and constant as the right op
  // regardless of how they appear in the original
  if (lhs_c && !rhs_c) {
    return {{rhs_val, lhs_c}};
  }

  if (rhs_c && !lhs_c) {
    return {{lhs_val, rhs_c}};
  }

  return std::nullopt;
}

// If the operator (op) is between an ICmpInst and a ConstantInt, return a
// tuple representing the ICmpInst and ConstantInt with tuple[0] holding the
// ICmpInst. Otherwise return `nullopt`.
static std::optional<std::tuple<llvm::ICmpInst *, llvm::ConstantInt *>>
getComparisonOperands(llvm::BinaryOperator *op) {

  // get the operands of this binaryop, and check that one is a constant int
  // and one is a variable
  if (auto ops = getVariableOperands(op)) {
    auto [var_op, const_op] = ops.value();
    // check if the variable op is a ICmp, if yes, succeed
    if (auto cmp = llvm::dyn_cast<llvm::ICmpInst>(var_op)) {
      return {{cmp, const_op}};
    }

    return std::nullopt;
  }

  return std::nullopt;
}

static llvm::Value *negateCmpPredicate(llvm::ICmpInst *cmp) {
  auto pred = cmp->getPredicate();
  llvm::IRBuilder<> ir(cmp);
  llvm::ICmpInst::Predicate new_pred = llvm::CmpInst::getInversePredicate(pred);

  // Create a new compare with negated predicate.
  return ir.CreateICmp(new_pred, cmp->getOperand(0), cmp->getOperand(1));
}

}  // namespace


llvm::PreservedAnalyses
ConvertXorsToCmps::run(llvm::Function &func,
                       llvm::FunctionAnalysisManager &AM) {
  std::vector<llvm::BinaryOperator *> xors;
  std::vector<llvm::BinaryOperator *> noncmp_xors;

  for (auto &inst : llvm::instructions(func)) {

    // check for binary op
    if (auto binop = llvm::dyn_cast<llvm::BinaryOperator>(&inst)) {

      // binary op is a xor
      if (binop->getOpcode() == llvm::Instruction::Xor) {

        // Get comparison operands of the xor. The caller ensures that one is a
        // compare and the other is a constant integer.
        if (auto cmp_ops = getComparisonOperands(binop)) {
          auto [_, cnst_int] = cmp_ops.value();

          // ensure that the constant int is 'true', or an i1 with the value 1
          // this (currently) the only supported value
          if (cnst_int->getType()->getBitWidth() == 1 &&
              cnst_int->isAllOnesValue()) {
            xors.emplace_back(binop);
          }
          continue;
        }

        if (auto xor_ops = getVariableOperands(binop)) {
          auto [_, cnst_int] = xor_ops.value();

          // ensure that the constant int is 'true', or an i1 with the value 1
          // this (currently) the only supported value
          if (cnst_int->getType()->getBitWidth() == 1 &&
              cnst_int->isAllOnesValue()) {
            noncmp_xors.emplace_back(binop);
          }
        }
      }
    }
  }

  auto changed = false;

  std::vector<llvm::BranchInst *> brs_to_invert;
  std::vector<llvm::SelectInst *> selects_to_invert;

  // look for things in the following pattern:
  // %20 = or i1 %19, i1 %18
  // %21 = xor i1 %20, i1 true
  // br i1 %21, label <left>, label <right>
  //
  // and change it to:
  //
  // %20 = or i1 %19, i1 %18
  // br i1 %20, label <right>, label <left>
  //
  for (auto ncmp_xor : noncmp_xors) {
    bool changed_this_xor = false;
    // These uses of xor followed by a branch can be simply replaced by switching branch conditions.
    // We invert the branch, and get rid of the xor, if it is unused.
    auto [var_op, _] = getVariableOperands(ncmp_xor).value();

    DLOG(INFO) << "Processing Xor: " << remill::LLVMThingToString(ncmp_xor)
               << "\n";
    // collect branches that use this xor
    llvm::SmallVector<llvm::BranchInst *, 2> brs_to_flip;
    for (auto &U : ncmp_xor->uses()) {
      if (auto br_inst = llvm::dyn_cast<llvm::BranchInst>(U.getUser())) {
        brs_to_flip.emplace_back(br_inst);
        DLOG(INFO) << "Will flip branch: " << remill::LLVMThingToString(br_inst)
                   << "\n";
      }
    }

    // invert the condition and swap the branch.
    // then we can remove the xors
    for (auto BR : brs_to_flip) {
      BR->setCondition(var_op);
      BR->swapSuccessors();
      // changed code globally
      changed = true;
      // changed this specific xor
      changed_this_xor = true;
    }

    if (changed_this_xor && ncmp_xor->use_empty()) {
      // this xor is no longer used, remove it
      ncmp_xor->eraseFromParent();
    }
  }

  // Look for xors specifically used in a comparison, and invert the comparison

  for (auto xori : xors) {

    // find predicate from xor's operands
    auto cmp_ops = getComparisonOperands(xori);
    if (!cmp_ops) {
      continue;
    }
    auto [cmp, _] = cmp_ops.value();

    bool invertible_xor = true;

    // so far, we have matched the following pattern:
    //
    //   %c = icmp PREDICATE v1, v2
    //   %x = xor i1 %c, true
    //
    // We want to to fold this cmp/xor pair into a cmp with an inverse
    // predicate, like so:
    //
    //   %c = icmp !PREDICATE v1, v2
    //   %x = %c
    //
    // BUT! Depending on how %c is used we may or may not be able to do that.
    //
    // We need to know if the result of the comparison (%c) is used elsewhere,
    // and how.
    //
    // We *can* still invert the cmp/xor pair if:
    // * All uses of this `cmp` are either a SelectInst or a BranchInst
    //    then we will invert every select and branch condition.
    //    this gets rid of the xor, and preserves program logic
    //
    // Examples:
    //  %si = select i1 %c, true_val, false_val
    //  br i1 %c, label %left, label %right
    //
    // We *cannot* invert the cmp/xor pair if:
    // * One or more uses of this `cmp` is *NOT* a SelectInst or a BranchInst
    //    The original value could be stored or used in some arithmetic op
    //    and we cannot freely invert the comparison, because it would change
    //    the logic of the program.
    //
    //    Most common example? A zext, like the following:
    //     %z = zext i1 %c to i64

    for (auto &U : cmp->uses()) {
      llvm::Instruction *inst = llvm::dyn_cast<llvm::Instruction>(U.getUser());

      // use is not the existing xor
      if (!inst || inst == xori) {
        continue;
      }

      brs_to_invert.clear();
      selects_to_invert.clear();

      llvm::BranchInst *br = llvm::dyn_cast<llvm::BranchInst>(inst);

      // A user of this compare is a BranchInstruction
      if (br) {
        brs_to_invert.emplace_back(br);
        continue;
      }

      llvm::SelectInst *si = llvm::dyn_cast<llvm::SelectInst>(inst);

      // A user of this compare is a SelectInst, and the compare is the
      // condition and not an operand.
      if (si && llvm::dyn_cast<llvm::ICmpInst>(si->getCondition()) == cmp) {
        selects_to_invert.emplace_back(si);
        continue;
      }

      invertible_xor = false;
      break;
    }

    // not inverting this branch
    if (!invertible_xor) {
      continue;
    }

    // negate predicate
    if (auto neg_cmp = negateCmpPredicate(cmp)) {
      CopyMetadataTo(xori, neg_cmp);

      // invert all branches
      for (auto B : brs_to_invert) {
        B->swapSuccessors();
      }

      // invert all selects
      for (auto SI : selects_to_invert) {
        SI->swapValues();
      }

      // replace uses of predicate with negated predicate
      cmp->replaceAllUsesWith(neg_cmp);

      // delete original predicate
      cmp->eraseFromParent();

      // replace uses of xor with negated predicate
      xori->replaceAllUsesWith(neg_cmp);

      // delte xor
      xori->eraseFromParent();
      changed = true;
    }
  }

  return ConvertBoolToPreserved(changed);
}


llvm::StringRef ConvertXorsToCmps::name(void) {
  return "ConvertXorsToCmps";
}

// Convert operations in the form of:
//      (left OP right) ^ 1
// into:
//      (left !OP right)
// this makes the output more natural for humans and computers to reason about
// This problem comes up a fair bit due to how some instruction semantics
// compute carry/parity/etc bits.
void AddConvertXorsToCmps(llvm::FunctionPassManager &fpm) {
  fpm.addPass(ConvertXorsToCmps());
}

}  // namespace anvill
