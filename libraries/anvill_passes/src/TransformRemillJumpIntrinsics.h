#pragma once

#include <anvill/Analysis/CrossReferenceResolver.h>
#include <anvill/Lifters/EntityLifter.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>

namespace anvill {

enum ReturnAddressResult {

  // This is a case where a value returned by `llvm.returnaddress`, or
  // casted from `__anvill_ra`, reaches into the `pc` argument of the
  // `__remill_jump` intrinsic. This is the ideal case that we want to
  // replace it with `__remill_function_return`.
  kReturnAddressProgramCounter,

  // This is a case a value returned by `llvm.returnaddress`, or casted
  // from `__anvill_ra` does not reaches to the `pc` argument and it
  // should not get transformed to `__remill_function_return`.
  kUnclassifiableProgramCounter
};

class TransformRemillJumpIntrinsics final
    : public llvm::PassInfoMixin<TransformRemillJumpIntrinsics> {
 public:
  TransformRemillJumpIntrinsics(const EntityLifter &lifter_)
      : xref_resolver_(lifter_) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

 private:
  ReturnAddressResult QueryReturnAddress(llvm::Module *module,
                                         llvm::Value *val) const;

  bool TransformJumpIntrinsic(llvm::CallBase *call);

  static char ID;
  const CrossReferenceResolver xref_resolver_;
};
}  // namespace anvill