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

#include <anvill/ABI.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Pass.h>
#include <glog/logging.h>
#include <vector>

namespace anvill {
namespace {

class ConvertXorToCmp final : public llvm::FunctionPass {
 public:
  ConvertXorToCmp(void)
      : llvm::FunctionPass(ID) {}

  bool runOnFunction(llvm::Function &func) override;

 private:
  static char ID;
};

char ConvertXorToCmp::ID = '\0';

// Get which operand for a binary operator is an ICmpInst
// nullptr if neither
static llvm::ICmpInst* getComparisonOperand(llvm::BinaryOperator *op) {
  auto rhs_cmp = llvm::dyn_cast<llvm::ICmpInst>(op->getOperand(1));
  if(rhs_cmp) {
    return rhs_cmp;
  }

  auto lhs_cmp = llvm::dyn_cast<llvm::ICmpInst>(op->getOperand(0));
  if(lhs_cmp) {
    return lhs_cmp;
  }

  return nullptr;
}

// from the LLVM documentation, we should handle the following comparisons
//ICMP_EQ 	equal
//ICMP_NE 	not equal
//ICMP_UGT 	unsigned greater than
//ICMP_UGE 	unsigned greater or equal
//ICMP_ULT 	unsigned less than
//ICMP_ULE 	unsigned less or equal
//ICMP_SGT 	signed greater than
//ICMP_SGE 	signed greater or equal
//ICMP_SLT 	signed less than
//ICMP_SLE 	signed less or equal
static llvm::Value* negateCmpPredicate(llvm::ICmpInst *cmp) {
  auto pred = cmp->getPredicate();
  llvm::IRBuilder<> ir(cmp);
  llvm::ICmpInst::Predicate new_pred = pred;

  switch(pred) {
    // equality
    case llvm::ICmpInst::ICMP_EQ:
      new_pred = llvm::ICmpInst::ICMP_NE;
      break;
    case llvm::ICmpInst::ICMP_NE:
      new_pred = llvm::ICmpInst::ICMP_EQ;
      break;

    // unsigned compares
    case llvm::ICmpInst::ICMP_UGT:
      new_pred = llvm::ICmpInst::ICMP_ULE;
      break;
    case llvm::ICmpInst::ICMP_UGE:
      new_pred = llvm::ICmpInst::ICMP_ULT;
      break;
    case llvm::ICmpInst::ICMP_ULT:
      new_pred = llvm::ICmpInst::ICMP_UGE;
      break;
    case llvm::ICmpInst::ICMP_ULE:
      new_pred = llvm::ICmpInst::ICMP_UGT;
      break;

    // signed compares
    case llvm::ICmpInst::ICMP_SGT:
      new_pred = llvm::ICmpInst::ICMP_SLE;
      break;
    case llvm::ICmpInst::ICMP_SGE:
      new_pred = llvm::ICmpInst::ICMP_SLT;
      break;
    case llvm::ICmpInst::ICMP_SLT:
      new_pred = llvm::ICmpInst::ICMP_SGE;
      break;
    case llvm::ICmpInst::ICMP_SLE:
      new_pred = llvm::ICmpInst::ICMP_SGT;
      break;

    default:
      // something we don't know; abort mission
      DLOG(ERROR) << "Error: encountered and unknown predicate type!";
      return nullptr;
  }

  // create a new compare with negated predicate
  return ir.CreateICmp(new_pred, cmp->getOperand(0), cmp->getOperand(1));
}

bool ConvertXorToCmp::runOnFunction(llvm::Function &func) {
  std::vector<llvm::BinaryOperator *> xors;

  for (auto &inst : llvm::instructions(func)) {
    // check for binary op
    if (auto binop = llvm::dyn_cast<llvm::BinaryOperator>(&inst)) {
      // binary op is a xor
      if (binop->getOpcode() == llvm::Instruction::Xor) {
        // xor has a constant as either lhs or rhs, and its a one-bit constant of size 1
        auto lhs_c = llvm::dyn_cast<llvm::ConstantInt>(binop->getOperand(0));
        auto lhs_cmp = llvm::dyn_cast<llvm::ICmpInst>(binop->getOperand(0));

        auto rhs_c = llvm::dyn_cast<llvm::ConstantInt>(binop->getOperand(1));
        auto rhs_cmp = llvm::dyn_cast<llvm::ICmpInst>(binop->getOperand(1));


        // left side is a constant int 1 (true), right side is a cmpinst
        if (lhs_c && lhs_c->getType()->getBitWidth() == 1 &&
            lhs_c->getValue() == 1 && rhs_cmp) {
          xors.emplace_back(binop);
        }

        // right side is a constant int 1 (true), left side is a cmp
        if (rhs_c && rhs_c->getType()->getBitWidth() == 1 &&
            rhs_c->getValue() == 1 && lhs_cmp) {
          xors.emplace_back(binop);
        }
      }
    }
  }

  auto changed = false;
  int replaced_items = 0;

  for (auto xori : xors) {
    // find predicate from xor's operands
    auto cmp = getComparisonOperand(xori);
    if(! cmp) {
      DLOG(ERROR) << "Error: Xor should have a comparison operand, but we can't find it again";
      continue;
    }
    // negate predicate
    auto neg_cmp = negateCmpPredicate(cmp);
    if(neg_cmp) {
      replaced_items += 1;

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

  LOG(INFO) << "ConvertXorToCmp: replaced " << replaced_items << " xors with negated comparisons";
  return changed;
}

}  // namespace

// Convert operations in the form of:
// (left OP right) ^ 1
// into:
// (left !OP right)
// this makes the output more natural for humans and computers to reason about
// This problem comes up a fair bit due to how some instruction semantics compute carry/parity/etc bits
llvm::FunctionPass *CreateConvertXorToCmp(void) {
  return new ConvertXorToCmp;
}

}  // namespace anvill
