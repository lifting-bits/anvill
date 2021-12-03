#pragma once

#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>


namespace anvill {
static constexpr auto kFlagIntrinsicPrefix = "__remill_flag_computation";
static constexpr auto kCompareInstrinsicPrefix = "__remill_compare";
class RemoveBranchAndFlagIntrinsics final
    : llvm::PassInfoMixin<RemoveBranchAndFlagIntrinsics> {
 public:
  explicit RemoveBranchAndFlagIntrinsics(void) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);


  static llvm::StringRef name(void);
};
}  // namespace anvill