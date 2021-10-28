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


class Environment {
 private:
  llvm::DenseMap<std::string, z3::expr> bindings;

 public:
  z3::expr lookup(const std::string &name) const {
    auto res = bindings.find(name);
    if (res == bindings.end()) {
      throw std::invalid_argument("Unbound variable: " + name);
    }

    return res->second;
  }
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
                           const Environment &env) const override {
    return env.lookup(name);
  }

  static std::unique_ptr<Expr> Create(std::string name) {
    return std::make_unique<AtomVariable>(std::move(name));
  }
};

class AtomIntExpr final : public Expr {
 private:
  llvm::APInt atom_value;

 public:
  static std::unique_ptr<bool[]> GetBigEndianBits(llvm::APInt api) {
    llvm::APInt toget_bits_from = api;

    // TODO(ian): verify endianess
    auto res = std::make_unique<bool[]>(toget_bits_from.getBitWidth());
    for (unsigned int i = 0; i < api.getBitWidth(); i++) {
      res[i] = toget_bits_from[i];
    }

    return res;
  }

  AtomIntExpr(llvm::APInt atomValue) : atom_value(atomValue) {}

  z3::expr BuildExpression(z3::context &c,
                           const Environment &env) const override {
    auto bv_width = this->atom_value.getBitWidth();
    auto bv_bits = AtomIntExpr::GetBigEndianBits(this->atom_value);
    return c.bv_val(bv_width, bv_bits.get());
  }

  static std::unique_ptr<Expr> Create(llvm::APInt value) {
    return std::make_unique<AtomIntExpr>(value);
  }
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
                                      std::unique_ptr<Expr> rhs) {
    return std::make_unique<BinopExpr>(opcode, std::move(lhs), std::move(rhs));
  }

  z3::expr BuildExpression(z3::context &c,
                           const Environment &env) const override {
    auto e1 = this->lhs->BuildExpression(c, env);
    auto e2 = this->rhs->BuildExpression(c, env);
    switch (this->opcode) {
      case ADD: return z3::operator+(e1, e2);
      case ULE: return z3::ule(e1, e2);
      case ULT: return z3::ult(e1, e2);
      case UGT: return z3::ugt(e1, e2);
      case UGE: return z3::uge(e1, e2);
      case SGT: return z3::sgt(e1, e2);
      case SGE: return z3::sge(e1, e2);
      case SLT: return z3::slt(e1, e2);
      case SLE: return z3::sle(e1, e2);
      case EQ: return z3::operator==(e1, e2);
      case AND: return z3::operator&&(e1, e2);
      case OR: return z3::operator||(e1, e2);
      default: throw std::invalid_argument("unknown opcode binop");
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

  static std::unique_ptr<Expr> Create(Z3Unop opcode,
                                      std::unique_ptr<Expr> lhs) {
    return std::make_unique<UnopExpr>(opcode, std::move(lhs));
  }

  z3::expr BuildExpression(z3::context &c,
                           const Environment &env) const override {
    auto e1 = this->lhs->BuildExpression(c, env);
    switch (this->opcode) {
      case Z3Unop::LOGNOT: return z3::operator!(e1);
      default: throw std::invalid_argument("unknown opcode unop");
    }
  }
};

template <typename UserVisitor>
class ConstraintExtractor
    : public llvm::InstVisitor<ConstraintExtractor,
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
    auto stp = static_cast<SubClass *>(this)->attemptStop(v);
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
