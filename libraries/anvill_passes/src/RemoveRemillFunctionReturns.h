#pragma once

#include <anvill/Analysis/CrossReferenceResolver.h>
#include <anvill/Lifters/EntityLifter.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>

namespace anvill {

enum ReturnAddressResult {

  // We've found a case where a value returned by `llvm.returnaddress`, or
  // casted from `__anvill_ra`, reaches into the `pc` argument of the
  // `__remill_function_return` intrinsic. This is the ideal case that we
  // want to handle.
  kFoundReturnAddress,

  // We've found a case where we're seeing a load from something derived from
  // `__anvill_sp`, our "symbolic stack pointer", is reaching into the `pc`
  // argument of `__remill_function_return`. This suggests that stack frame
  // recovery has not happened yet, and thus we haven't really given stack
  // frame recovery or stack frame splitting a chance to work.
  kFoundSymbolicStackPointerLoad,

  // We've found a `load` or something else. This is probably a sign that
  // stack frame recovery has happened, and that the actual return address
  // is not necessarily the expected value, and so we need to try to swap
  // out the return address with whatever we loaded.
  kUnclassifiableReturnAddress
};

class RemoveRemillFunctionReturns final
    : public llvm::PassInfoMixin<RemoveRemillFunctionReturns> {
 public:
  RemoveRemillFunctionReturns(const EntityLifter &lifter_)
      : xref_resolver(lifter_) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

 private:
  ReturnAddressResult QueryReturnAddress(llvm::Module *module,
                                         llvm::Value *val) const;

  const CrossReferenceResolver xref_resolver;
};
}  // namespace anvill