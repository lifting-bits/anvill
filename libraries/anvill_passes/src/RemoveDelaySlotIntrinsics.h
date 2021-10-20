#pragma once

#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>


class RemoveDelaySlotIntrinsics final
    : public llvm::PassInfoMixin<RemoveDelaySlotIntrinsics> {
 public:
  RemoveDelaySlotIntrinsics(void) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);
};
