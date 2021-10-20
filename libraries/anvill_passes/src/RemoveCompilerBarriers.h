#pragma once

#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>

namespace anvill {
class RemoveCompilerBarriers final
    : public llvm::PassInfoMixin<RemoveCompilerBarriers> {
 public:
  RemoveCompilerBarriers(void) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);
};
}  // namespace anvill