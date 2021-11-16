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
    case AND:
      if (e1.is_bv()) {
        return z3::operator&(e1, e2);
      } else {
        return z3::operator&&(e1, e2);
      }
    case OR:
      if (e1.is_bv()) {
        return z3::operator|(e1, e2);
      } else {
        return z3::operator||(e1, e2);
      }

    case XOR: return e1 ^ e2;
    default: throw std::invalid_argument("unknown opcode binop");
  }
}

z3::expr BinopExpr::BuildExpression(z3::context &c,
                                    const Environment &env) const {
  auto e1 = this->lhs->BuildExpression(c, env);
  auto e2 = this->rhs->BuildExpression(c, env);

  if (e1.is_bool() && !e2.is_bool()) {
    // If it's well typed then we should have a 1 bit
    assert(e2.is_bv() && e2.get_sort().bv_size() == 1);
    return BinopExpr::ExpressionFromLhsRhs(
        this->opcode, e1,
        e2 != c.bv_val(1,
                       AtomIntExpr::GetBigEndianBits(llvm::APInt(1, 0)).get()));
  } else if (e2.is_bool() && !e1.is_bool()) {
    // If it's well typed then we should have a 1 bit
    assert(e1.is_bv() && e1.get_sort().bv_size() == 1);
    return BinopExpr::ExpressionFromLhsRhs(
        this->opcode,
        e1 !=
            c.bv_val(1, AtomIntExpr::GetBigEndianBits(llvm::APInt(1, 0)).get()),
        e2);
  }

  assert(!e1.is_bv() || e1.get_sort().bv_size() == e2.get_sort().bv_size());


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

z3::expr Sext::BuildExpression(z3::context &c, const Environment &env) const {
  auto texpr = this->target->BuildExpression(c, env);
  return z3::sext(texpr, this->target_size);
}

std::unique_ptr<Expr> Sext::Create(std::unique_ptr<Expr> target,
                                   unsigned size) {
  return std::make_unique<Sext>(std::move(target), size);
}

z3::expr Zext::BuildExpression(z3::context &c, const Environment &env) const {
  auto texpr = this->target->BuildExpression(c, env);
  return z3::zext(texpr, this->target_size);
}

std::unique_ptr<Expr> Zext::Create(std::unique_ptr<Expr> target,
                                   unsigned size) {
  return std::make_unique<Zext>(std::move(target), size);
}


z3::expr Trunc::BuildExpression(z3::context &c, const Environment &env) const {
  auto texpr = this->target->BuildExpression(c, env);
  return texpr.extract(this->hi, this->lo);
}

std::unique_ptr<Expr> Trunc::Create(std::unique_ptr<Expr> target, unsigned hi,
                                    unsigned lo) {
  return std::make_unique<Trunc>(std::move(target), hi, lo);
}


}  // namespace anvill