#pragma once

#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>


namespace anvill {
class LowerRemillUndefinedIntrinsics final
    : public llvm::PassInfoMixin<LowerRemillUndefinedIntrinsics> {
 public:
  LowerRemillUndefinedIntrinsics(void) {}


  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);
};
}  // namespace anvill