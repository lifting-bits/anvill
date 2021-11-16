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


#pragma once

#include <anvill/Constraints.h>
#include <anvill/SliceManager.h>
#include <anvill/Transforms.h>
#include <llvm/ADT/SmallSet.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/Analysis/CFG.h>
#include <llvm/ExecutionEngine/Interpreter.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/PatternMatch.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <z3++.h>

namespace anvill {


template <typename UserVisitor>
class ConstraintExtractor
    : public llvm::InstVisitor<UserVisitor,
                               std::optional<std::unique_ptr<Expr>>> {
 private:
 public:
  std::optional<llvm::Instruction *> substituded_index;
  std::optional<std::unique_ptr<Expr>>
  ExpectInsnOrStopCondition(llvm::Value *v) {
    auto stp = static_cast<UserVisitor *>(this)->attemptStop(v);
    if (stp.has_value()) {
      return stp;
    }

    if (auto *constint = llvm::dyn_cast<llvm::ConstantInt>(v)) {
      return AtomIntExpr::Create(constint->getValue());
    }

    if (auto *insn = llvm::dyn_cast<llvm::Instruction>(v)) {
      return this->visit(*insn);
    }

    return std::nullopt;
  }


  ConstraintExtractor() {}

  std::optional<std::unique_ptr<Expr>> visitInstruction(llvm::Instruction &I) {
    return std::nullopt;
  }


  std::optional<std::unique_ptr<Expr>> visitSExt(llvm::SExtInst &I) {
    if (auto repr0 = this->ExpectInsnOrStopCondition(I.getOperand(0))) {
      auto diff = I.getDestTy()->getIntegerBitWidth() -
                  I.getSrcTy()->getIntegerBitWidth();
      return Sext::Create(std::move(*repr0), diff);
    }
    return std::nullopt;
  }

  std::optional<std::unique_ptr<Expr>> visitZExt(llvm::ZExtInst &I) {
    if (auto repr0 = this->ExpectInsnOrStopCondition(I.getOperand(0))) {
      auto diff = I.getDestTy()->getIntegerBitWidth() -
                  I.getSrcTy()->getIntegerBitWidth();
      return Zext::Create(std::move(*repr0), diff);
    }
    return std::nullopt;
  }

  std::optional<std::unique_ptr<Expr>> visitTrunc(llvm::TruncInst &I) {
    if (auto repr0 = this->ExpectInsnOrStopCondition(I.getOperand(0))) {
      auto diff = I.getSrcTy()->getIntegerBitWidth() -
                  I.getDestTy()->getIntegerBitWidth();

      // hi lo are [hi,lo] inclusive
      auto old_hi = I.getSrcTy()->getIntegerBitWidth() - 1;
      auto new_hi = old_hi - diff;
      return Trunc::Create(std::move(*repr0), new_hi, 0);
    }
    return std::nullopt;
  }


  std::optional<std::unique_ptr<Expr>> visitICmpInst(llvm::ICmpInst &I) {
    auto conn = BinopExpr::TranslateIcmpOpToZ3(I.getPredicate());


    if (auto repr0 = this->ExpectInsnOrStopCondition(I.getOperand(0))) {
      if (auto repr1 = this->ExpectInsnOrStopCondition(I.getOperand(1))) {
        if (conn) {
          return {
              BinopExpr::Create(*conn, std::move(*repr0), std::move(*repr1))};
        }
      }
    }

    return std::nullopt;
  }

  std::optional<std::unique_ptr<Expr>>
  visitBinaryOperator(llvm::BinaryOperator &B) {
    auto conn = BinopExpr::TranslateOpcodeToConnective(B.getOpcode());


    if (auto repr0 = this->ExpectInsnOrStopCondition(B.getOperand(0))) {
      if (auto repr1 = this->ExpectInsnOrStopCondition(B.getOperand(1))) {
        if (conn) {
          return {
              BinopExpr::Create(*conn, std::move(*repr0), std::move(*repr1))};
        }
      }
    }

    return std::nullopt;
  }
};


}  // namespace anvill