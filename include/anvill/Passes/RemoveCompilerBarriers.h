#pragma once

#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>

namespace anvill {
class RemoveCompilerBarriers final
    : llvm::PassInfoMixin<RemoveCompilerBarriers> {
 public:
  explicit RemoveCompilerBarriers(void) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);


  static llvm::StringRef name(void);
};
}  // namespace anvill