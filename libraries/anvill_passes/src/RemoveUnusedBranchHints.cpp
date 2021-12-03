#include "RemoveUnusedBranchHints.h"
namespace anvill {


RemoveUnusedBranchHints::Result
RemoveUnusedBranchHints::runOnIntrinsic(llvm::CallInst *indirectJump,
                                        llvm::FunctionAnalysisManager &am,

                                        RemoveUnusedBranchHints::Result agg) {
  auto real_res = indirectJump->getArgOperand(0);
  indirectJump->replaceAllUsesWith(real_res);
  indirectJump->eraseFromParent();
  return llvm::PreservedAnalyses::none();
}

RemoveUnusedBranchHints::Result RemoveUnusedBranchHints::INIT_RES =
    llvm::PreservedAnalyses::all();


void AddRemoveFailedBranchHints(llvm::FunctionPassManager &fpm) {
  fpm.addPass(RemoveUnusedBranchHints());
}

llvm::StringRef RemoveUnusedBranchHints::name() {
  return "RemoveUnusedBranchHints";
}

}  // namespace anvill