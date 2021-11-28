/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <anvill/Lifters.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>

namespace anvill {

class CrossReferenceFolder;
class CrossReferenceResolver;

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
 private:
  const CrossReferenceResolver &xref_resolver;


  ReturnAddressResult QueryReturnAddress(
      const CrossReferenceFolder &xref_folder, llvm::Module *module,
      llvm::Value *val) const;

  bool TransformJumpIntrinsic(llvm::CallBase *call);

 public:
  inline TransformRemillJumpIntrinsics(
      const CrossReferenceResolver &xref_resolver_)
      : xref_resolver(xref_resolver_) {}

  static llvm::StringRef name(void);

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);
};
}  // namespace anvill
