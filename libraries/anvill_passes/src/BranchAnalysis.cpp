#include <anvill/BranchAnalysis.h>
#include <anvill/ConstraintExtractor.h>
#include <anvill/Constraints.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <remill/BC/IntrinsicTable.h>

#include <exception>
#include <iostream>
#include <unordered_map>

namespace anvill {
// TODO:(ian) should replace this with a generic pass over a given set of intrinsics to merge with inidrect jump passes
namespace {

const std::unordered_map<std::string, llvm::CmpInst::Predicate> CompPredMap = {
    {"sle", llvm::CmpInst::Predicate::ICMP_SLE},
    {"slt", llvm::CmpInst::Predicate::ICMP_SLT},
    {"ult", llvm::CmpInst::Predicate::ICMP_ULT},
    {"ule", llvm::CmpInst::Predicate::ICMP_ULE},
    {"sge", llvm::CmpInst::Predicate::ICMP_SGE},
    {"sgt", llvm::CmpInst::Predicate::ICMP_SGT},
    {"ugt", llvm::CmpInst::Predicate::ICMP_UGT},
    {"uge", llvm::CmpInst::Predicate::ICMP_UGE},
    {"eq", llvm::CmpInst::Predicate::ICMP_EQ},
    {"neq", llvm::CmpInst::Predicate::ICMP_NE}};

const std::unordered_map<std::string, ArithFlags> FlagPredMap = {
    {"zero", ArithFlags::ZF},
    {"overflow", ArithFlags::OF},
    {"sign", ArithFlags::SIGN},
    {"carry", ArithFlags::CARRY}};


struct FlagDefinition {
  llvm::Value *lhs;
  llvm::Value *rhs;
  Z3Binop binop;
  ArithFlags flagres;
  llvm::Type *resultTy;
};


class EnvironmentBuilder {

 private:
  std::optional<ComparedValues> symbols;
  std::unordered_map<std::string, FlagDefinition> bindings;
  uint64_t id_counter;

 public:
  static std::string getValueName(uint64_t number) {
    return "value" + std::to_string(number);
  }

 private:
  std::string nextID() {
    return FlagIDPrefix + std::to_string(this->id_counter++);
  }


  std::optional<FlagDefinition> parseFlagDefinition(RemillFlag rf) {
    std::optional<Z3Binop> conn = std::nullopt;
    std::optional<llvm::Value *> lhs = std::nullopt;
    std::optional<llvm::Value *> rhs = std::nullopt;
    if (auto *binop = llvm::dyn_cast<llvm::BinaryOperator>(rf.over)) {
      conn = BinopExpr::TranslateOpcodeToConnective(binop->getOpcode());
      lhs = binop->getOperand(0);
      rhs = binop->getOperand(1);
    } else if (auto *binop = llvm::dyn_cast<llvm::ICmpInst>(rf.over)) {
      conn = BinopExpr::TranslateIcmpOpToZ3(binop->getPredicate());
      lhs = binop->getOperand(0);
      rhs = binop->getOperand(1);
    }

    if (conn && lhs && rhs) {
      return {{*lhs, *rhs, *conn, rf.flg, rf.over->getType()}};
    }


    return std::nullopt;
  }

  bool composedOfSameSymbols(FlagDefinition flagdef) {
    return !this->symbols || ((this->symbols->first == flagdef.lhs ||
                               this->symbols->first == flagdef.rhs) &&
                              (this->symbols->second == flagdef.lhs ||
                               this->symbols->second == flagdef.rhs));
  }

  bool areIntegerTypes(FlagDefinition flagdef) {
    return flagdef.lhs->getType()->isIntegerTy() &&
           flagdef.rhs->getType()->isIntegerTy();
  }

 public:
  EnvironmentBuilder()
      : symbols(std::nullopt),
        bindings(std::unordered_map<std::string, FlagDefinition>()),
        id_counter(0) {}

  inline const static std::string FlagIDPrefix = "flag";


  std::optional<std::unique_ptr<Expr>> addFlag(RemillFlag rf) {
    auto flagdef = this->parseFlagDefinition(rf);
    if (flagdef.has_value() && this->composedOfSameSymbols(*flagdef) &&
        this->areIntegerTypes(*flagdef)) {
      this->symbols = {std::make_pair(flagdef->lhs, flagdef->rhs)};
      auto name = this->nextID();
      this->bindings.insert({name, *flagdef});
      return {AtomVariable::Create(name)};
    }

    return std::nullopt;
  }

  z3::expr create_flag_for_name(z3::context &cont, std::string name) {
    return cont.bool_const(name.c_str());
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

  z3::expr get_expr_for_binop(llvm::Value *v, const Environment &env) {
    if (v == this->symbols->first) {
      return env.lookup(EnvironmentBuilder::getValueName(0));
    } else if (v == this->symbols->second) {
      return env.lookup(EnvironmentBuilder::getValueName(1));
    }

    throw std::invalid_argument(
        "Expression Builder has value in flagdef that is not one of the symbols");
  }


  static z3::expr get_constant_in_z3(z3::context &cont, llvm::Type *ty,
                                     uint64_t constant) {
    auto bits = AtomIntExpr::GetBigEndianBits(
        llvm::APInt(ty->getIntegerBitWidth(), constant));
    return cont.bv_val(ty->getIntegerBitWidth(), bits.get());
  }


  static std::optional<z3::expr>
  get_overflow_flag(z3::context &cont, z3::expr binop_res, z3::expr lhs,
                    z3::expr rhs, FlagDefinition flagdef) {


    z3::expr zero =
        EnvironmentBuilder::get_constant_in_z3(cont, flagdef.resultTy, 0);
    z3::expr sign_lhs = z3::slt(lhs, EnvironmentBuilder::get_constant_in_z3(
                                         cont, flagdef.lhs->getType(), 0));
    z3::expr sign_rhs = z3::slt(rhs, EnvironmentBuilder::get_constant_in_z3(
                                         cont, flagdef.rhs->getType(), 0));
    z3::expr binop_sign = z3::slt(
        binop_res,
        EnvironmentBuilder::get_constant_in_z3(cont, flagdef.resultTy, 0));
    // TODO(ian): need overflow semantics for mul
    switch (flagdef.binop) {
      case Z3Binop::ADD:
        return (sign_lhs ^ binop_sign) && (sign_rhs ^ binop_sign);
      case Z3Binop::SUB:
        return (sign_lhs ^ sign_rhs) && (sign_lhs ^ binop_sign);

      default: return std::nullopt;
    }
  }

  static std::optional<z3::expr>
  get_carry_flag(z3::context &cont, z3::expr binop_res, z3::expr lhs,
                 z3::expr rhs, FlagDefinition flagdef) {

    switch (flagdef.binop) {
      case Z3Binop::ADD:
        return z3::ult(binop_res, lhs) || z3::ult(binop_res, rhs);
      case Z3Binop::SUB: return z3::ult(lhs, rhs);

      default: return std::nullopt;
    }
  }


  std::optional<z3::expr>
  get_flag_assertion(z3::context &cont, z3::expr binop_res, z3::expr lhs,
                     z3::expr rhs, FlagDefinition flagdef) {
    switch (flagdef.flagres) {
      case ArithFlags::ZF:
        return binop_res == EnvironmentBuilder::get_constant_in_z3(
                                cont, flagdef.resultTy, 0);
      case ArithFlags::SIGN:
        return binop_res < EnvironmentBuilder::get_constant_in_z3(
                               cont, flagdef.resultTy, 0);
      case ArithFlags::OF:
        return EnvironmentBuilder::get_overflow_flag(cont, binop_res, lhs, rhs,
                                                     flagdef);
      case ArithFlags::CARRY:
        return EnvironmentBuilder::get_carry_flag(cont, binop_res, lhs, rhs,
                                                  flagdef);
      default: throw std::runtime_error("unsupported arithmetic flag");
    }
  }

  bool define_flag_in_context(z3::context &cont, z3::solver &solver,
                              const Environment &env, FlagDefinition flagdef,
                              z3::expr flag_expr) {

    auto lhs = this->get_expr_for_binop(flagdef.lhs, env);
    auto rhs = this->get_expr_for_binop(flagdef.rhs, env);
    auto binop = BinopExpr::ExpressionFromLhsRhs(flagdef.binop, lhs, rhs);
    auto flag_assertion = get_flag_assertion(cont, binop, lhs, rhs, flagdef);

    if (flag_assertion.has_value()) {
      solver.add(flag_expr == *flag_assertion);
      return true;
    } else {
      return false;
    }
  }

  std::optional<std::pair<Environment, ComparedValues>>
  BuildEnvironment(z3::context &cont, z3::solver &solver) {
    if (!symbols.has_value()) {
      return std::nullopt;
    }

    Environment env;

    auto symbs = this->symbols_as_z3(cont, env);

    for (auto pr : this->bindings) {

      auto flag_expr = this->create_flag_for_name(cont, pr.first);
      env.insert(pr.first, flag_expr);

      if (!this->define_flag_in_context(cont, solver, env, pr.second,
                                        flag_expr)) {
        return std::nullopt;
      }
    }
    return {std::make_pair(env, *this->symbols)};
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
    auto flag_semantics = ParseFlagIntrinsic(value);
    if (flag_semantics.has_value()) {
      auto res = envBuilder.addFlag(*flag_semantics);
      return res;
    } else {
      return std::nullopt;
    }
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
        auto value = call->getArgOperand(call->getNumArgOperands() - 1);
        return {{flag_repr->second, value}};
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
  intrinsic_call->getFunction()->dump();
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