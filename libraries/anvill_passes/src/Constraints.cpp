#include <anvill/Constraints.h>


namespace anvill {

z3::expr Environment::lookup(const std::string &name) const {
  auto res = bindings.find(name);
  if (res == bindings.end()) {
    throw std::invalid_argument("Unbound variable: " + name);
  }

  return res->second;
}

void Environment::insert(std::string name, z3::expr value) {
  this->bindings.insert({name, value});
}


z3::expr AtomVariable::BuildExpression(z3::context &c,
                                       const Environment &env) const {
  return env.lookup(name);
}

std::unique_ptr<Expr> AtomVariable::Create(std::string name) {
  return std::make_unique<AtomVariable>(std::move(name));
}

std::unique_ptr<bool[]> AtomIntExpr::GetBigEndianBits(llvm::APInt api) {
  llvm::APInt toget_bits_from = api;

  // TODO(ian): verify endianess
  auto res = std::make_unique<bool[]>(toget_bits_from.getBitWidth());
  for (unsigned int i = 0; i < api.getBitWidth(); i++) {
    res[i] = toget_bits_from[i];
  }

  return res;
}

z3::expr AtomIntExpr::BuildExpression(z3::context &c,
                                      const Environment &env) const {
  auto bv_width = this->atom_value.getBitWidth();
  auto bv_bits = AtomIntExpr::GetBigEndianBits(this->atom_value);
  return c.bv_val(bv_width, bv_bits.get());
}

std::unique_ptr<Expr> AtomIntExpr::Create(llvm::APInt value) {
  return std::make_unique<AtomIntExpr>(value);
}

std::unique_ptr<Expr> BinopExpr::Create(Z3Binop opcode,
                                        std::unique_ptr<Expr> lhs,
                                        std::unique_ptr<Expr> rhs) {
  return std::make_unique<BinopExpr>(opcode, std::move(lhs), std::move(rhs));
}


z3::expr BinopExpr::ExpressionFromLhsRhs(Z3Binop opcode, z3::expr e1,
                                         z3::expr e2) {
  switch (opcode) {
    case ADD: return z3::operator+(e1, e2);
    case SUB: return z3::operator-(e1, e2);
    case ULE: return z3::ule(e1, e2);
    case ULT: return z3::ult(e1, e2);
    case UGT: return z3::ugt(e1, e2);
    case UGE: return z3::uge(e1, e2);
    case SGT: return z3::sgt(e1, e2);
    case SGE: return z3::sge(e1, e2);
    case SLT: return z3::slt(e1, e2);
    case SLE: return z3::sle(e1, e2);
    case EQ: return z3::operator==(e1, e2);
    case NEQ: return z3::operator!=(e1, e2);
    case AND: return z3::operator&&(e1, e2);
    case OR: return z3::operator||(e1, e2);
    case XOR: return e1 ^ e2;
    default: throw std::invalid_argument("unknown opcode binop");
  }
}
z3::expr BinopExpr::BuildExpression(z3::context &c,
                                    const Environment &env) const {
  auto e1 = this->lhs->BuildExpression(c, env);
  auto e2 = this->rhs->BuildExpression(c, env);
  return BinopExpr::ExpressionFromLhsRhs(this->opcode, e1, e2);
}

std::unique_ptr<Expr> UnopExpr::Create(Z3Unop opcode,
                                       std::unique_ptr<Expr> lhs) {
  return std::make_unique<UnopExpr>(opcode, std::move(lhs));
}


z3::expr UnopExpr::BuildExpression(z3::context &c,
                                   const Environment &env) const {
  auto e1 = this->lhs->BuildExpression(c, env);
  switch (this->opcode) {
    case Z3Unop::LOGNOT: return z3::operator!(e1);
    default: throw std::invalid_argument("unknown opcode unop");
  }
}

}  // namespace anvill