#pragma once

#include <anvill/BranchAnalysis.h>
#include <anvill/BranchHintPass.h>


namespace anvill {
class BranchRecovery
    : public BranchHintPass<BranchRecovery, llvm::PreservedAnalyses>,
      llvm::PassInfoMixin<BranchRecovery> {
 public:
  // Maps CallInst to anvill_compare prims to the result
  using Result = llvm::PreservedAnalyses;

  static Result INIT_RES;


  Result runOnIntrinsic(llvm::CallInst *indirectJump,
                        llvm::FunctionAnalysisManager &am, Result agg);


  static llvm::StringRef name();
};
}  // namespace anvill