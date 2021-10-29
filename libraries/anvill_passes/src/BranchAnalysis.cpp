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
    {"sle", llvm::CmpInst::Predicate::ICMP_SLE}};

const std::unordered_map<std::string, ArithFlags> FlagPredMap = {
    {"zero", ArithFlags::ZF},
    {"overflow", ArithFlags::ZF},
    {"sign", ArithFlags::SIGN}};

static bool isTargetInstrinsic(const llvm::CallInst *callinsn) {
  if (const auto *callee = callinsn->getCalledFunction()) {
    return callee->getName().startswith(kCompareInstrinsicPrefix);
  }

  return false;
}
static inline std::vector<llvm::CallInst *>
getTargetCalls(llvm::Function &fromFunction) {
  std::vector<llvm::CallInst *> calls;
  for (auto &insn : llvm::instructions(fromFunction)) {
    llvm::Instruction *new_insn = &insn;
    if (llvm::CallInst *call_insn = llvm::dyn_cast<llvm::CallInst>(new_insn)) {
      if (isTargetInstrinsic(call_insn)) {
        calls.push_back(call_insn);
      }
    }
  }
  return calls;
}

}  // namespace

std::optional<RemillFlag> ParseFlagIntrinsic(llvm::Value *value) {
  if (auto *call = llvm::dyn_cast<llvm::CallInst>(value)) {
    if (call->getCalledFunction()->getName().startswith(kFlagIntrinsicPrefix)) {
      auto suffix = call->getCalledFunction()->getName().rsplit('_');
      auto flag_repr = FlagPredMap.find(suffix.second.str());
      if (flag_repr != FlagPredMap.end()) {
        auto value = call->getArgOperand(1);
        return {{flag_repr->second, value}};
      }
    }
  }
  return std::nullopt;
}


struct FlagDefinition {
  llvm::Value *lhs;
  llvm::Value *rhs;
  Z3Binop binop;
  ArithFlags flagres;
  llvm::Type *resultTy;
};

class EnvironmentBuilder {
 private:
  std::optional<std::pair<llvm::Value *, llvm::Value *>> symbols;
  std::unordered_map<std::string, FlagDefinition> bindings;
  uint64_t id_counter;


 private:
  std::string nextID() {
    return FlagIDPrefix + std::to_string(this->id_counter++);
  }

  static std::string getValueName(uint64_t number) {
    return "value" + std::to_string(number);
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
      this->bindings.insert({this->nextID(), *flagdef});
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

  z3::expr get_flag_assertion(z3::context &cont, z3::expr flag_name,
                              z3::expr binop_res, z3::expr lhs, z3::expr rhs,
                              FlagDefinition flagdef) {
    switch (flagdef.flagres) {
      case ArithFlags::ZF:
        return binop_res == EnvironmentBuilder::get_constant_in_z3(
                                cont, flagdef.resultTy, 0);
      case ArithFlags::SIGN:
        return binop_res < EnvironmentBuilder::get_constant_in_z3(
                               cont, flagdef.resultTy, 0);
      default: throw std::runtime_error("unsupported arithmetic flag");
    }
  }

  void define_flag_in_context(z3::context &cont, z3::solver &solver,
                              const Environment &env, FlagDefinition flagdef,
                              z3::expr flag_expr) {

    auto lhs = this->get_expr_for_binop(flagdef.lhs, env);
    auto rhs = this->get_expr_for_binop(flagdef.rhs, env);
    auto binop = BinopExpr::ExpressionFromLhsRhs(flagdef.binop, lhs, rhs);
    auto flag_assertion = get_flag_assertion(cont, binop, lhs, rhs, flagdef);
    solver.add(flag_expr == flag_assertion);
  }

  std::optional<Environment> BuildEnvironment(z3::context &cont,
                                              z3::solver &solver) {
    if (!symbols.has_value()) {
      return std::nullopt;
    }

    Environment env;

    auto symbs = this->symbols_as_z3(cont, env);

    for (auto pr : this->bindings) {
      auto flag_expr = this->create_flag_for_name(cont, pr.first);
      env.insert(pr.first, flag_expr);

      this->define_flag_in_context(cont, solver, env, pr.second, flag_expr);
    }
    return env;
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
      return envBuilder.addFlag(*flag_semantics);
    } else {
      return std::nullopt;
    }
  }
};


RemillComparison ParseComparisonIntrinsic(llvm::StringRef intrinsic_name) {
  auto cmpname = intrinsic_name.rsplit('_').second;
  auto pred = CompPredMap.find(cmpname.str());
  if (pred == CompPredMap.end()) {
    throw std::runtime_error(
        ("Unrecogonized predicate in compare intrinsic " + cmpname).str());
  }

  return {pred->second};
}

const std::string kFlagIntrinsicPrefix("__remill_flag_computation");
const std::string kCompareInstrinsicPrefix("__remill_compare");

std::optional<BranchResult>
BranchAnalysis::analyzeComparison(llvm::CallInst *intrinsic_call) {
  auto pred =
      ParseComparisonIntrinsic(intrinsic_call->getCalledFunction()->getName());
  return std::nullopt;
}

llvm::AnalysisKey BranchAnalysis::Key;


BranchAnalysis::Result BranchAnalysis::run(llvm::Function &F,
                                           llvm::FunctionAnalysisManager &am) {
  Result res;
  for (auto targetcompare : getTargetCalls(F)) {
    auto analysis_result = this->analyzeComparison(targetcompare);
    if (analysis_result) {
      res.insert({targetcompare, *analysis_result});
    }
  }
  return res;
}

llvm::StringRef BranchAnalysis::name() {
  return "BranchAnalysis";
}
}  // namespace anvill