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


  virtual std::optional<std::unique_ptr<Expr>> attemptStop(llvm::Value *v) = 0;

  std::optional<std::unique_ptr<Expr>> visitInstruction(llvm::Instruction &I) {
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