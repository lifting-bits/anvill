#include <anvill/BranchAnalysis.h>
#include <anvill/Providers/MemoryProvider.h>
#include <anvill/Transforms.h>
#include <doctest.h>
#include <llvm/ADT/SmallSet.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>

#include <iostream>

#include "Utils.h"
namespace anvill {

namespace {

static llvm::Function *FindFunction(llvm::Module *module, std::string name) {
  for (auto &function : *module) {
    if (function.getName().equals(name)) {
      return &function;
    }
  }
  return nullptr;
}
}  // namespace

TEST_SUITE("BranchRecoveryPass") {
  TEST_CASE("Run on sliced function sub") {
    llvm::LLVMContext context;
    SliceManager slc;
    auto mod = LoadTestData(context, "RecoverSubBranch.ll");
    auto target_function = FindFunction(mod.get(), "slice");
    CHECK(target_function != nullptr);
    llvm::FunctionPassManager fpm;
    llvm::FunctionAnalysisManager fam;
    llvm::LoopAnalysisManager lam;
    llvm::CGSCCAnalysisManager cgam;
    llvm::ModuleAnalysisManager mam;

    llvm::PassBuilder pb;
    pb.registerFunctionAnalyses(fam);
    pb.registerCGSCCAnalyses(cgam);
    pb.registerLoopAnalyses(lam);
    pb.registerModuleAnalyses(mam);

    pb.crossRegisterProxies(lam, fam, cgam, mam);

    fpm.addPass(llvm::InstCombinePass());


    fam.registerPass([&] { return llvm::DominatorTreeAnalysis(); });
    fam.registerPass([&] { return BranchAnalysis(); });


    fpm.run(*target_function, fam);
    auto res = fam.getResult<BranchAnalysis>(*target_function);

    llvm::CallInst *target_compare = nullptr;
    for (auto &insn : llvm::instructions(target_function)) {
      if (auto *cll = llvm::dyn_cast<llvm::CallInst>(&insn)) {
        if (cll->getCalledFunction()->getName().startswith(
                kCompareInstrinsicPrefix)) {
          target_compare = cll;
        }
      }
    }

    REQUIRE(target_compare != nullptr);

    auto result = res.find(target_compare);

    REQUIRE(result != res.end());

    auto branch_analysis = result->second;

    CHECK(branch_analysis.compare == llvm::CmpInst::Predicate::ICMP_SLE);
    CHECK(branch_analysis.compared.first == target_function->getArg(2));
    CHECK(branch_analysis.compared.second == target_function->getArg(1));

    lam.clear();
    fam.clear();
    cgam.clear();
    mam.clear();
  }


  TEST_CASE("Run on sliced function sub") {
    llvm::LLVMContext context;
    SliceManager slc;
    auto mod = LoadTestData(context, "UnrecoverableBranch.ll");
    auto target_function = FindFunction(mod.get(), "slice");
    CHECK(target_function != nullptr);
    llvm::FunctionPassManager fpm;
    llvm::FunctionAnalysisManager fam;
    llvm::LoopAnalysisManager lam;
    llvm::CGSCCAnalysisManager cgam;
    llvm::ModuleAnalysisManager mam;

    llvm::PassBuilder pb;
    pb.registerFunctionAnalyses(fam);
    pb.registerCGSCCAnalyses(cgam);
    pb.registerLoopAnalyses(lam);
    pb.registerModuleAnalyses(mam);

    pb.crossRegisterProxies(lam, fam, cgam, mam);

    fpm.addPass(llvm::InstCombinePass());


    fam.registerPass([&] { return llvm::DominatorTreeAnalysis(); });
    fam.registerPass([&] { return BranchAnalysis(); });


    fpm.run(*target_function, fam);
    auto res = fam.getResult<BranchAnalysis>(*target_function);

    CHECK(res.empty());

    lam.clear();
    fam.clear();
    cgam.clear();
    mam.clear();
  }
}

}  // namespace anvill