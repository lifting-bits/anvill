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

 public:
  EnvironmentBuilder()
      : symbols(std::nullopt),
        bindings(std::unordered_map<std::string, FlagDefinition>()),
        id_counter(0) {}

  inline const static std::string FlagIDPrefix = "flag";


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
      rhs = binop->getOperand(0);
    }

    if (conn && lhs && rhs) {
      return {{*lhs, *rhs, *conn, rf.flg}};
    }


    return std::nullopt;
  }

  bool composedOfSameSymbols(FlagDefinition flagdef) {
    return !this->symbols || ((this->symbols->first == flagdef.lhs ||
                               this->symbols->first == flagdef.rhs) &&
                              (this->symbols->second == flagdef.lhs ||
                               this->symbols->second == flagdef.rhs));
  }

  std::optional<std::unique_ptr<Expr>> addFlag(RemillFlag rf) {
    auto flagdef = this->parseFlagDefinition(rf);

    if (flagdef.has_value() && this->composedOfSameSymbols(*flagdef)) {
      this->symbols = {std::make_pair(flagdef->lhs, flagdef->rhs)};
      this->bindings.insert({this->nextID(), *flagdef});
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