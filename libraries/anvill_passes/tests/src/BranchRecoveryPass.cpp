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
  TEST_CASE("Run on sliced function") {
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

    lam.clear();
    fam.clear();
    cgam.clear();
    mam.clear();
  }
}

}  // namespace anvill