
#include "RemoveBranchAndFlagIntrinsics.h"

#include <llvm/IR/InstIterator.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/Casting.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>

namespace anvill {

llvm::PreservedAnalyses
RemoveBranchAndFlagIntrinsics::run(llvm::Function &F,
                                   llvm::FunctionAnalysisManager &AM) {

  std::vector<llvm::Instruction *> to_del;
  for (auto &insn : llvm::instructions(F)) {
    if (auto *call = llvm::dyn_cast<llvm::CallBase>(&insn)) {
      auto name = call->getCalledFunction()->getName();
      if (name.startswith(kFlagIntrinsicPrefix) ||
          name.startswith(kCompareInstrinsicPrefix)) {


        call->replaceAllUsesWith(call->getArgOperand(0));
        to_del.push_back(call);
      }
    }
  }

  for (auto c : to_del) {
    c->eraseFromParent();
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