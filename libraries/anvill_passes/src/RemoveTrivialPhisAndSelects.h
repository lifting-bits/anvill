#pragma once

#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>

namespace anvill {

class RemoveTrivialPhisAndSelects final
    : public llvm::PassInfoMixin<RemoveTrivialPhisAndSelects> {
 public:
  RemoveTrivialPhisAndSelects(void) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);
};

}  // namespace anvill
