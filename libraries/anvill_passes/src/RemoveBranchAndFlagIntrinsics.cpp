
#include "RemoveBranchAndFlagIntrinsics.h"

#include <llvm/IR/InstIterator.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/Casting.h>
namespace anvill {

llvm::PreservedAnalyses
RemoveBranchAndFlagIntrinsics::run(llvm::Function &F,
                                   llvm::FunctionAnalysisManager &AM) {

  for (auto &insn : llvm::instructions(F)) {
    if (auto *call = llvm::dyn_cast<llvm::CallBase>(&insn)) {
      auto name = call->getCalledFunction()->getName();
      if (name.startswith(kFlagIntrinsicPrefix) ||
          name.startswith(kCompareInstrinsicPrefix)) {

        call->replaceAllUsesWith(call->getArgOperand(0));
        call->eraseFromParent();
      }
    }
  }


  return llvm::PreservedAnalyses::none();
}


llvm::StringRef RemoveBranchAndFlagIntrinsics::name(void) {
  return "RemoveBranchAndFlagIntrinsics";
}

void AddRemoveComparisonAndBranchIntrinsics(llvm::FunctionPassManager &fpm) {
  fpm.addPass(RemoveBranchAndFlagIntrinsics());
}
}  // namespace anvill