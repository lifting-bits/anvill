#pragma once

#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>


namespace anvill {

class LowerRemillMemoryAccessIntrinsics final
    : public llvm::PassInfoMixin<LowerRemillMemoryAccessIntrinsics> {
 public:
  LowerRemillMemoryAccessIntrinsics(void) {}


  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);
};
}  // namespace anvill