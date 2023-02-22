
#pragma once

#include <anvill/Passes/BasicBlockPass.h>
#include <llvm/IR/PassManager.h>
#include <remill/BC/Util.h>

#include "anvill/Lifters.h"


namespace anvill {

// attempts to replace assignments to next pc with idiomatic control flow that terminates the block
// with the goto intrinsic
class RemoveAssignmentsToNextPC final
    : public BasicBlockPass<RemoveAssignmentsToNextPC> {
 private:
  const EntityLifter &lifter;

 public:
  RemoveAssignmentsToNextPC(const BasicBlockContexts &contexts,
                            const EntityLifter &lifter)
      : BasicBlockPass(contexts),
        lifter(lifter) {}

  static llvm::StringRef name(void);


  llvm::PreservedAnalyses
  runOnBasicBlockFunction(llvm::Function &F, llvm::FunctionAnalysisManager &AM,
                          const anvill::BasicBlockContext &);
};
}  // namespace anvill