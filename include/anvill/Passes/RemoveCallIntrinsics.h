
#pragma once

#include <anvill/CrossReferenceFolder.h>
#include <anvill/Passes/IntrinsicPass.h>
#include <llvm/IR/PassManager.h>

#include "anvill/Lifters.h"
#include "anvill/Specification.h"


namespace anvill {
/**
 * @brief Attempts to remove call intrinsics by identifying a type for the target of a remill_call and lifting the arguments
 * types are either provided by a recovered entity or folding the reference to an address that has an override type.
 */
class RemoveCallIntrinsics final
    : public IntrinsicPass<RemoveCallIntrinsics, llvm::PreservedAnalyses>,
      public llvm::PassInfoMixin<RemoveCallIntrinsics> {
 private:
  const CrossReferenceResolver &xref_resolver;
  const Specification &spec;
  const EntityLifter &lifter;

 public:
  RemoveCallIntrinsics(const CrossReferenceResolver &xref_resolver,
                       const Specification &spec, const EntityLifter &lifter)
      : xref_resolver(xref_resolver),
        spec(spec),
        lifter(lifter) {}

  llvm::PreservedAnalyses runOnIntrinsic(llvm::CallInst *indirectJump,
                                         llvm::FunctionAnalysisManager &am,
                                         llvm::PreservedAnalyses);


  static llvm::PreservedAnalyses INIT_RES;


  static bool isTargetInstrinsic(const llvm::CallInst *callinsn);
  static llvm::StringRef name();
};

}  // namespace anvill