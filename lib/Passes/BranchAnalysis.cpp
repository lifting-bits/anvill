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


#include <anvill/Passes/BranchAnalysis.h>
#include <anvill/Passes/ConstraintExtractor.h>
#include <anvill/Passes/Constraints.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <remill/BC/IntrinsicTable.h>

#include <exception>
#include <iostream>
#include <unordered_map>

namespace anvill {
namespace {

static const std::unordered_map<std::string, llvm::CmpInst::Predicate>
    CompPredMap = {{"sle", llvm::CmpInst::Predicate::ICMP_SLE},
                   {"slt", llvm::CmpInst::Predicate::ICMP_SLT},
                   {"ult", llvm::CmpInst::Predicate::ICMP_ULT},
                   {"ule", llvm::CmpInst::Predicate::ICMP_ULE},
                   {"sge", llvm::CmpInst::Predicate::ICMP_SGE},
                   {"sgt", llvm::CmpInst::Predicate::ICMP_SGT},
                   {"ugt", llvm::CmpInst::Predicate::ICMP_UGT},
                   {"uge", llvm::CmpInst::Predicate::ICMP_UGE},
                   {"eq", llvm::CmpInst::Predicate::ICMP_EQ},
                   {"neq", llvm::CmpInst::Predicate::ICMP_NE}};

static const std::unordered_map<std::string, ArithFlags> FlagPredMap = {
    {"zero", ArithFlags::ZF},
    {"overflow", ArithFlags::OF},
    {"sign", ArithFlags::SIGN},
    {"carry", ArithFlags::CARRY}};


class EnvironmentBuilder {

 private:
  std::optional<ComparedValues> symbols;
  uint64_t id_counter;

 public:
  static std::string getValueName(uint64_t number) {
    return "value" + std::to_string(number);
  }

 private:
  std::string nextID() {
    return FlagIDPrefix + std::to_string(this->id_counter++);
  }

  bool composedOfSameSymbols(RemillFlag flagdef) {
    return !this->symbols || ((this->symbols->first == flagdef.lhs ||
                               this->symbols->first == flagdef.rhs) &&
                              (this->symbols->second == flagdef.lhs ||
                               this->symbols->second == flagdef.rhs));
  }

  static bool areIntegerTypes(RemillFlag flagdef) {
    return flagdef.lhs->getType()->isIntegerTy() &&
           flagdef.rhs->getType()->isIntegerTy();
  }

 public:
  EnvironmentBuilder() : symbols(std::nullopt), id_counter(0) {}

  inline const static std::string FlagIDPrefix = "flag";


  std::optional<llvm::Value *> addFlag(RemillFlag rf) {
    if (this->composedOfSameSymbols(rf) && areIntegerTypes(rf)) {
      if (!this->symbols.has_value()) {
        this->symbols = {std::make_pair(rf.lhs, rf.rhs)};
      }

      return {rf.flag_val};
    }

    return std::nullopt;
  }

  std::pair<z3::expr, z3::expr> symbols_as_z3(z3::context &cont,
                                              Environment &env) {
    auto v1name = EnvironmentBuilder::getValueName(0);
    auto v2name = EnvironmentBuilder::getValueName(1);
    auto v1 = cont.bv_const(
        v1name.c_str(), this->symbols->first->getType()->getIntegerBitWidth());
    auto v2 = cont.bv_const(
        v2name.c_str(), this->symbols->first->getType()->getIntegerBitWidth());

    env.insert(v1name, v1);
    env.insert(v2name, v2);

    return std::make_pair(v1, v2);
  }

  std::optional<std::pair<Environment, ComparedValues>>
  BuildEnvironment(z3::context &cont, z3::solver &solver) {
    if (!symbols.has_value()) {
      return std::nullopt;
    }

    Environment env;

    auto symbs = this->symbols_as_z3(cont, env);
    return {std::make_pair(env, *this->symbols)};
  }

  std::optional<std::unique_ptr<Expr>> getSymbolFor(llvm::Value *tgt) {
    if (this->symbols) {
      if (tgt == this->symbols->first) {
        return {AtomVariable::Create(EnvironmentBuilder::getValueName(0))};
      }

      if (tgt == this->symbols->second) {
        return {AtomVariable::Create(EnvironmentBuilder::getValueName(1))};
      }
    }

    return std::nullopt;
  }
};


class LocalConstraintExtractor
    : public ConstraintExtractor<LocalConstraintExtractor> {
 private:
  EnvironmentBuilder &envBuilder;

 public:
  LocalConstraintExtractor(EnvironmentBuilder &envBuilder)
      : envBuilder(envBuilder) {}

  std::optional<std::unique_ptr<Expr>> attemptStop(llvm::Value *value) {
    auto symbol_for = envBuilder.getSymbolFor(value);
    if (symbol_for.has_value()) {
      return symbol_for;
    }

    auto flag_semantics = ParseFlagIntrinsic(value);
    if (flag_semantics.has_value()) {
      auto res = envBuilder.addFlag(*flag_semantics);
      if (res.has_value()) {
        return this->ExpectInsnOrStopCondition(*res);
      }
    }

    return std::nullopt;
  }
};


}  // namespace

std::optional<RemillFlag> ParseFlagIntrinsic(const llvm::Value *value) {
  if (auto *call = llvm::dyn_cast<llvm::CallInst>(value)) {
    auto called = call->getCalledFunction();
    if (called != nullptr &&
        called->getName().startswith(kFlagIntrinsicPrefix)) {
      auto suffix = call->getCalledFunction()->getName().rsplit('_');
      auto flag_repr = FlagPredMap.find(suffix.second.str());
      if (flag_repr != FlagPredMap.end()) {
        // the arithmetic result that the flag was computed over is the last operand
        auto flag_val = call->getArgOperand(0);
        auto lhs = call->getArgOperand(1);
        auto rhs = call->getArgOperand(2);
        auto over = call->getArgOperand(3);
        return {{flag_repr->second, flag_val, lhs, rhs, over}};
      }
    }
  }
  return std::nullopt;
}

// (declare-fun value1 () (_ BitVec 64))
// (declare-fun value0 () (_ BitVec 64))
// (declare-fun flag2 () Bool)
// (declare-fun flag1 () Bool)
// (declare-fun flag0 () Bool)
// (declare-fun flagRes () Bool)

// (assert (= (or flag0 (xor flag1 flag2)) flagRes))

// (declare-fun value1neg () (_ BitVec 64))
// (assert (let ((a!1 (and (xor (bvslt value1 #x0000000000000000)
//                      (bvslt (bvadd value0 value1) #x0000000000000000))
//                 (xor (bvslt value0 #x0000000000000000)
//                      (bvslt (bvadd value0 value1) #x0000000000000000)))))
//   (= flag2 a!1)))
// (assert (= flag1 (bvslt (bvadd value0 value1) #x0000000000000000)))
// (assert (= flag0 (= (bvadd value0 value1) #x0000000000000000)))
// (assert (not (= value1 (bvshl #x0000000000000001 #x000000000000003f))))

// (assert (or (and flagRes (not (bvsle value0 (bvneg value1))) )
//  (and  (bvsle value0 (bvneg value1))  (not flagRes)        )))

// (check-sat)
// (get-model)


// Proof of a sle via add ish. So the question is with negatives do we allow proving with inclusion of no wrap assertion (assert (not (= value1 (bvshl #x0000000000000001 #x000000000000003f))))
// The proof is then bvsle or value = wrap.
RemillComparison ParseComparisonIntrinsic(llvm::StringRef intrinsic_name) {
  auto cmpname = intrinsic_name.rsplit('_').second;
  auto pred = CompPredMap.find(cmpname.str());
  if (pred == CompPredMap.end()) {
    throw std::runtime_error(
        ("Unrecogonized predicate in compare intrinsic " + cmpname).str());
  }

  return {pred->second};
}

Guess::Guess(llvm::CmpInst::Predicate op, bool flip_symbols)
    : op(op),
      flip_symbols(flip_symbols) {
  // enforce z3 modeling at construction
  auto z3res = BinopExpr::TranslateIcmpOpToZ3(this->op);
  assert(z3res.has_value());
  this->z3_op = *z3res;
}

BranchResult Guess::ConstructSimplifiedCondition(ComparedValues symb) {
  if (this->flip_symbols) {
    symb = {symb.second, symb.first};
  }

  return {symb, this->op};
}

bool Guess::AttemptToProve(z3::expr flagRes, z3::solver &solv,
                           z3::context &cont, const Environment &env) {
  solv.push();

  auto v0 = env.lookup(EnvironmentBuilder::getValueName(0));
  auto v1 = env.lookup(EnvironmentBuilder::getValueName(1));
  auto v0final = flip_symbols ? v1 : v0;
  auto v1final = flip_symbols ? v0 : v1;

  auto guessexpr =
      BinopExpr::ExpressionFromLhsRhs(this->z3_op, v0final, v1final);

  auto guess_implies_flag_cex = guessexpr && (!flagRes);
  auto flag_implies_guess_cex = flagRes && (!guessexpr);

  solv.add(guess_implies_flag_cex || flag_implies_guess_cex);

  auto proven = solv.check() == z3::unsat;

  solv.pop();
  return proven;
}

std::optional<BranchResult>
BranchAnalysis::analyzeComparison(llvm::CallInst *intrinsic_call) {
  auto pred =
      ParseComparisonIntrinsic(intrinsic_call->getCalledFunction()->getName());
  EnvironmentBuilder envbuilder;
  LocalConstraintExtractor consextract(envbuilder);


  auto expr =
      consextract.ExpectInsnOrStopCondition(intrinsic_call->getArgOperand(0));
  if (expr.has_value()) {
    z3::context c;
    z3::solver s(c);
    auto env_and_symbols = envbuilder.BuildEnvironment(c, s);
    if (env_and_symbols.has_value()) {
      auto env = env_and_symbols->first;
      auto symbols = env_and_symbols->second;
      auto exp = expr->get()->BuildExpression(c, env);
      for (const auto &strat : this->guess_generation_strategies) {
        auto res = strat(pred.pred);
        if (res.AttemptToProve(exp, s, c, env)) {
          BranchResult cmp = res.ConstructSimplifiedCondition(symbols);
          return {cmp};
        }
      }
    }
  }


  return std::nullopt;
}


BranchAnalysis::Result BranchAnalysis::INIT_RES = BranchAnalysis::Result();


BranchAnalysis::Result
BranchAnalysis::runOnIntrinsic(llvm::CallInst *call,
                               llvm::FunctionAnalysisManager &am,
                               BranchAnalysis::Result agg) {
  auto mayberes = this->analyzeComparison(call);
  if (mayberes.has_value()) {
    agg.insert({call, *mayberes});
  }

  return agg;
}


llvm::AnalysisKey BranchAnalysis::Key;


llvm::StringRef BranchAnalysis::name() {
  return "BranchAnalysis";
}
}  // namespace anvill