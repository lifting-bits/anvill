#include <anvill/Passes/BasicBlockPass.h>
#include <llvm/IR/PassManager.h>

#include "anvill/Lifters.h"

namespace anvill {
// An intrinsic pass that currently assumes that the function returns to its caller,
// replacing the sound remill return with an anvill_return that returns the value specified by this
// functions ABI.
// TODO(Ian): make intrinsic pass compose with basic block passes somehow
class ReplaceRemillFunctionReturnsWithAnvillFunctionReturns
    : public BasicBlockPass<
          ReplaceRemillFunctionReturnsWithAnvillFunctionReturns> {
 private:
  const EntityLifter &lifter;

 public:
  ReplaceRemillFunctionReturnsWithAnvillFunctionReturns(
      const BasicBlockContexts &contexts, const EntityLifter &lifter)
      : BasicBlockPass(contexts),
        lifter(lifter) {}

  static llvm::StringRef name(void);


  llvm::PreservedAnalyses
  runOnBasicBlockFunction(llvm::Function &F, llvm::FunctionAnalysisManager &AM,
                          const anvill::BasicBlockContext &,
                          const FunctionDecl &);
};
}  // namespace anvill