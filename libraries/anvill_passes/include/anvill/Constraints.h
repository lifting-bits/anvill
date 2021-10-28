#pragma once

#include <llvm/ADT/APInt.h>
#include <llvm/ADT/StringMap.h>
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

// might be able to combine complex formula with binop tbh
// this technically allows (x /\ y) + (a /\ b) should maybe prevent these from being constructed, currently relies on the visitor to check and not construct.
enum Z3Binop { ADD, ULE, ULT, UGT, UGE, AND, OR, EQ, SGT, SGE, SLE, SLT };
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
  z3::expr BuildExpression(z3::context &c,
                           const Environment &env) const override;
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