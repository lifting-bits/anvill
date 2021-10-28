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
  static std::optional<Z3Binop>
  TranslateOpcodeToConnective(llvm::Instruction::BinaryOps op) {
    switch (op) {
      case llvm::Instruction::BinaryOps::And /* constant-expression */:
        /* code */
        return {Z3Binop::AND};
      case llvm::Instruction::BinaryOps::Or: return {Z3Binop::OR};
      case llvm::Instruction::BinaryOps::Add: return {Z3Binop::ADD};
      default: return std::nullopt;
    }
  }


  static std::optional<Z3Binop>
  TranslateIcmpOpToZ3(llvm::CmpInst::Predicate op) {
    switch (op) {
      case llvm::CmpInst::Predicate::ICMP_EQ: return Z3Binop::EQ;
      case llvm::CmpInst::Predicate::ICMP_UGE: return Z3Binop::UGE;
      case llvm::CmpInst::Predicate::ICMP_UGT: return Z3Binop::UGT;
      case llvm::CmpInst::Predicate::ICMP_ULE: return Z3Binop::ULE;
      case llvm::CmpInst::Predicate::ICMP_ULT: return Z3Binop::ULT;
      case llvm::CmpInst::Predicate::ICMP_SGE: return Z3Binop::SGE;
      case llvm::CmpInst::Predicate::ICMP_SGT: return Z3Binop::SGT;
      case llvm::CmpInst::Predicate::ICMP_SLE: return Z3Binop::SLE;
      case llvm::CmpInst::Predicate::ICMP_SLT: return Z3Binop::SLT;
      default: return std::nullopt;
    }
  }

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
    auto conn = TranslateIcmpOpToZ3(I.getPredicate());


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
    auto conn = TranslateOpcodeToConnective(B.getOpcode());


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