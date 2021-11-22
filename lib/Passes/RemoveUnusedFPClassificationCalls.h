#pragma once

#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>


namespace anvill {

class RemoveUnusedFPClassificationCalls final
    : public llvm::PassInfoMixin<RemoveUnusedFPClassificationCalls> {
 public:
  RemoveUnusedFPClassificationCalls(void) {}

  llvm::PreservedAnalyses run(llvm::Function &function,
                              llvm::FunctionAnalysisManager &analysisManager);
};
}  // namespace anvill