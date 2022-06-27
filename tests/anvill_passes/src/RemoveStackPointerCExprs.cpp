#include <anvill/Passes/RemoveStackPointerCExprs.h>

#include <anvill/Transforms.h>
#include <doctest.h>
#include <llvm/ADT/SmallSet.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <anvill/Lifters.h>
#include <iostream>

#include "Utils.h"
namespace anvill {

static llvm::Function *FindFunction(llvm::Module *module, std::string name) {
  for (auto &function : *module) {
    if (function.getName().equals(name)) {
      return &function;
    }
  }
  return nullptr;
}

TEST_SUITE("RemoveStackPointerCExprs") {
  TEST_CASE("RegressionRecoverStack.ll") {
    auto llvm_context = anvill::CreateContextWithOpaquePointers();
    auto mod = LoadTestData(*llvm_context, "RegressionRecoverStack.ll");
    auto target_function = FindFunction(mod.get(), "slice");
    CHECK(target_function != nullptr);
    llvm::FunctionPassManager fpm;
    llvm::FunctionAnalysisManager fam;
    llvm::ModuleAnalysisManager mam;
    llvm::LoopAnalysisManager lam;
    llvm::CGSCCAnalysisManager cgam;

    llvm::PassBuilder pb;

    pb.registerFunctionAnalyses(fam);
    pb.registerModuleAnalyses(mam);
    pb.registerCGSCCAnalyses(cgam);
    pb.registerLoopAnalyses(lam);

    pb.crossRegisterProxies(lam, fam, cgam, mam);

    StackFrameRecoveryOptions opt;
    fpm.addPass(RemoveStackPointerCExprs(opt));
    fpm.run(*target_function, fam);

    target_function->dump();

    CHECK(VerifyModule(mod.get()));

    fam.clear();
    cgam.clear();
    lam.clear();
    mam.clear();
  }
}
}  // namespace anvill
