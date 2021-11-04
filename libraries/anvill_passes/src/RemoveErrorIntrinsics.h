#pragma once

#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>


namespace anvill {

class RemoveErrorIntrinsics final
    : public llvm::PassInfoMixin<RemoveErrorIntrinsics> {
 public:
  RemoveErrorIntrinsics(void) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);
};

}  // namespace anvill