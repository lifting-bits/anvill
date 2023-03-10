#pragma once

#include <llvm/IR/PassManager.h>

namespace anvill {
class RemoveAnvillReturns final
    : public llvm::PassInfoMixin<RemoveAnvillReturns> {
 public:
  RemoveAnvillReturns(void) {}

  static llvm::StringRef name(void);

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);
};
}  // namespace anvill
