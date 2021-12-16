#include <anvill/Passes/BranchAnalysis.h>
#include <anvill/Passes/BranchHintPass.h>
#include <anvill/Passes/IntrinsicPass.h>


namespace anvill {

// This pass consumes the analysis from BranchAnalysis and replaces the compare intrinsic
// with an icmp of the form icmp compare compared.0 compared.1 which was proven equivalent to the flag
// computation.

class RemoveUnusedBranchHints
    : public IntrinsicPass<RemoveUnusedBranchHints, llvm::PreservedAnalyses>,
      llvm::PassInfoMixin<RemoveUnusedBranchHints> {
 public:
  // Maps CallInst to anvill_compare prims to the result
  using Result = llvm::PreservedAnalyses;

  static Result INIT_RES;


  static bool isTargetInstrinsic(const llvm::CallInst *callinsn) {
    if (const auto *callee = callinsn->getCalledFunction()) {
      return callee->getName().startswith(kCompareInstrinsicPrefix) ||
             callee->getName().startswith(kFlagIntrinsicPrefix);
    }

    return false;
  }


  Result runOnIntrinsic(llvm::CallInst *indirectJump,
                        llvm::FunctionAnalysisManager &am, Result agg);


  static llvm::StringRef name();
};
}  // namespace anvill