#pragma once

#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>

namespace anvill {

class LowerTypeHintIntrinsics final
    : public llvm::PassInfoMixin<LowerTypeHintIntrinsics> {
 public:
  LowerTypeHintIntrinsics(void) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);
};

}  // namespace anvill