#include <anvill/JumpTableAnalysis.h>
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
    JumpTableAnalysis *jta = new JumpTableAnalysis(slc);
    auto mod = LoadTestData(context, "RecoverableBranch.ll");
    auto target_function = FindFunction(mod.get(), "slice");
    CHECK(target_function != nullptr);
    llvm::legacy::FunctionPassManager fpm(mod.get());
    fpm.add(llvm::createInstructionCombiningPass());
    fpm.add(new llvm::DominatorTreeWrapperPass());
    fpm.add(jta);
  }
}

}  // namespace anvill