#include <anvill/BranchAnalysis.h>
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