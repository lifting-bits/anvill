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

#include <llvm/ADT/APInt.h>
#include <llvm/ADT/StringMap.h>
#include <llvm/IR/Instructions.h>
#include <z3++.h>

#include <memory>
#include <unordered_map>

namespace anvill {
class Environment {
 private:
  std::unordered_map<std::string, z3::expr> bindings;

 public:
  Environment() {}


  z3::expr lookup(const std::string &name) const;
  void insert(std::string name, z3::expr value);
};

class Expr {
 public:
  virtual ~Expr() = default;
  virtual z3::expr BuildExpression(z3::context &c,
                                   const Environment &env) const = 0;
};


// Casts must always handle bitvectors, if we recieve a bool, upcast to a bitvector
class Cast : public Expr {
 private:
  std::unique_ptr<Expr> target;

 public:
  Cast(std::unique_ptr<Expr> target) : target(std::move(target)) {}

  z3::expr BuildExpression(z3::context &c,
                           const Environment &env) const override;


  virtual z3::expr BuildExpressionFromEvaluated(z3::expr target) const = 0;

  virtual ~Cast() = default;
};


class Sext final : public Cast {
 private:
  unsigned target_size;

 public:
  Sext(std::unique_ptr<Expr> target, unsigned target_size)
      : Cast(std::move(target)),
        target_size(target_size) {}

  z3::expr BuildExpressionFromEvaluated(z3::expr target) const override;

  static std::unique_ptr<Expr> Create(std::unique_ptr<Expr> target,
                                      unsigned size);
};

class Zext final : public Cast {
 private:
  unsigned target_size;

 public:
  Zext(std::unique_ptr<Expr> target, unsigned target_size)
      : Cast(std::move(target)),
        target_size(target_size) {}

  z3::expr BuildExpressionFromEvaluated(z3::expr target) const override;

  static std::unique_ptr<Expr> Create(std::unique_ptr<Expr> target,
                                      unsigned size);
};

class Trunc final : public Cast {
 private:
  unsigned hi;
  unsigned lo;

 public:
  Trunc(std::unique_ptr<Expr> target, unsigned hi, unsigned lo)
      : Cast(std::move(target)),
        hi(hi),
        lo(lo) {}

  z3::expr BuildExpressionFromEvaluated(z3::expr target) const override;

  static std::unique_ptr<Expr> Create(std::unique_ptr<Expr> target, unsigned hi,
                                      unsigned lo);
};


class AtomVariable final : public Expr {
 private:
  std::string name;

 public:
  AtomVariable(std::string name) : name(std::move(name)) {}

  z3::expr BuildExpression(z3::context &c,
                           const Environment &env) const override;

  static std::unique_ptr<Expr> Create(std::string name);
};

class AtomIntExpr final : public Expr {
 private:
  llvm::APInt atom_value;

 public:
  static std::unique_ptr<bool[]> GetBigEndianBits(llvm::APInt api);

  AtomIntExpr(llvm::APInt atomValue) : atom_value(atomValue) {}

  z3::expr BuildExpression(z3::context &c,
                           const Environment &env) const override;

  static std::unique_ptr<Expr> Create(llvm::APInt value);
};

//NOTE(ian): this technically allows (x /\ y) + (a /\ b) should maybe prevent these from being constructed, currently relies on the visitor to check and not construct.
enum Z3Binop {
  ADD,
  SUB,
  ULE,
  ULT,
  UGT,
  UGE,
  MUL,
  AND,
  OR,
  EQ,
  SGT,
  SGE,
  SLE,
  SLT,
  XOR,
  NEQ
};
class BinopExpr final : public Expr {
 private:
  Z3Binop opcode;
  std::unique_ptr<Expr> lhs;
  std::unique_ptr<Expr> rhs;

 public:
  BinopExpr(Z3Binop opcode, std::unique_ptr<Expr> lhs,
            std::unique_ptr<Expr> rhs)
      : opcode(opcode),
        lhs(std::move(lhs)),
        rhs(std::move(rhs)) {}


  static std::unique_ptr<Expr> Create(Z3Binop opcode, std::unique_ptr<Expr> lhs,
                                      std::unique_ptr<Expr> rhs);

  static z3::expr ExpressionFromLhsRhs(Z3Binop opcode, z3::expr lhs,
                                       z3::expr rhs);

  z3::expr BuildExpression(z3::context &c,
                           const Environment &env) const override;

  static std::optional<Z3Binop>
  TranslateOpcodeToConnective(llvm::Instruction::BinaryOps op) {
    switch (op) {
      case llvm::Instruction::BinaryOps::And /* constant-expression */:
        /* code */
        return {Z3Binop::AND};
      case llvm::Instruction::BinaryOps::Or: return {Z3Binop::OR};
      case llvm::Instruction::BinaryOps::Add: return {Z3Binop::ADD};
      case llvm::Instruction::BinaryOps::Sub: return {Z3Binop::SUB};
      case llvm::Instruction::BinaryOps::Xor: return {Z3Binop::XOR};
      default: return std::nullopt;
    }
  }


  static std::optional<Z3Binop>
  TranslateIcmpOpToZ3(llvm::CmpInst::Predicate op) {
    switch (op) {
      case llvm::CmpInst::Predicate::ICMP_EQ: return Z3Binop::EQ;
      case llvm::CmpInst::Predicate::ICMP_NE: return Z3Binop::NEQ;
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
};

enum Z3Unop { LOGNOT };
class UnopExpr final : public Expr {
 private:
  Z3Unop opcode;
  std::unique_ptr<Expr> lhs;

 public:
  UnopExpr(Z3Unop opcode, std::unique_ptr<Expr> lhs)
      : opcode(opcode),
        lhs(std::move(lhs)) {}

  static std::unique_ptr<Expr> Create(Z3Unop opcode, std::unique_ptr<Expr> lhs);

  z3::expr BuildExpression(z3::context &c, const Environment &env) const;
};
}  // namespace anvill