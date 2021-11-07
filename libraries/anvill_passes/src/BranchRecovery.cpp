#include "BranchRecovery.h"

#include <llvm/Transforms/Utils/BasicBlockUtils.h>

namespace anvill {

void AddBranchRecovery(llvm::FunctionPassManager &fpm) {
  fpm.addPass(BranchRecovery());
}

BranchRecovery::Result BranchRecovery::INIT_RES =
    llvm::PreservedAnalyses::all();

llvm::StringRef BranchRecovery::name() {
  return "BranchRecovery";
}

BranchRecovery::Result
BranchRecovery::runOnIntrinsic(llvm::CallInst *brcond,
                               llvm::FunctionAnalysisManager &am, Result agg) {
  auto res = am.getResult<BranchAnalysis>(*brcond->getFunction());
  auto brres = res.find(brcond);
  if (brres != res.end()) {
    auto ba = brres->second;
    llvm::ReplaceInstWithInst(
        brcond,
        new llvm::ICmpInst(ba.compare, ba.compared.first, ba.compared.second));

    agg.intersect(llvm::PreservedAnalyses::none());
  }

  return agg;
}
}  // namespace anvill