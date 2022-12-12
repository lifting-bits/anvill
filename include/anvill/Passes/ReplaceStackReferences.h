
#pragma once

#include <anvill/Passes/BasicBlockPass.h>
#include <llvm/IR/PassManager.h>

#include "anvill/Lifters.h"


namespace anvill {
/**
 * @brief Replaces references to anvill_pc +- disp with a pointer to the represented local variable.
 * If variable information seperatates variables that are actually overlapping this pass may separate variables in an unsound way.
 */
class ReplaceStackReferences final
    : public BasicBlockPass<ReplaceStackReferences> {
 private:
  const EntityLifter &lifter;

 public:
  ReplaceStackReferences(const BasicBlockContexts &contexts,
                         const EntityLifter &lifter)
      : BasicBlockPass(contexts),
        lifter(lifter) {}

  static llvm::StringRef name(void);


  llvm::PreservedAnalyses
  runOnBasicBlockFunction(llvm::Function &F, llvm::FunctionAnalysisManager &AM,
                          const anvill::BasicBlockContext &);
};
}  // namespace anvill