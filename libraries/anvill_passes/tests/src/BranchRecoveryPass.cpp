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

    lam.clear();
    fam.clear();
    cgam.clear();
    mam.clear();
  }


  //   (declare-fun value1 () (_ BitVec 64))
  // (declare-fun value0 () (_ BitVec 64))
  // (declare-fun flag2 () Bool)
  // (declare-fun flag1 () Bool)
  // (declare-fun flag0 () Bool)
  // (declare-fun guessExpr () Bool)


  // (declare-fun ofValue () (_ BitVec 64))
  // (assert (= ofValue (bvshl #x0000000000000001 #x000000000000003f)))

  // (assert (= guessExpr (or (bvsle value0 (bvneg value1) ) (= value1 ofValue))
  // ))


  // (assert (let ((a!1 (and (xor (bvslt value0 #x0000000000000000)
  //                      (bvslt (bvadd value0 value1) #x0000000000000000))
  //                 (xor (bvslt value1 #x0000000000000000)
  //                      (bvslt (bvadd value0 value1) #x0000000000000000)))))
  //   (= flag2 a!1)))
  // (assert (= flag1 (bvslt (bvadd value0 value1) #x0000000000000000)))
  // (assert (= flag0 (= (bvadd value0 value1) #x0000000000000000)))
  // (assert (let ((a!1 (and  guessExpr
  //                 (not (or flag0 (xor flag1 flag2)))))
  //       (a!2 (and (or flag0 (xor flag1 flag2))
  //                 (not guessExpr))))
  //   (or a!1 a!2)))


  // (check-sat)
  // (get-model)
  // Tightest bound we can get on an add is that it is sle or an overflow value (should we transform these)

  TEST_CASE("Run on sliced function add") {
    llvm::LLVMContext context;
    SliceManager slc;
    auto mod = LoadTestData(context, "RecoverableBranch.ll");
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