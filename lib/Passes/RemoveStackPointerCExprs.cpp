/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Passes/RemoveStackPointerCExprs.h>

#include <anvill/CrossReferenceFolder.h>
#include <anvill/CrossReferenceResolver.h>
#include <anvill/Lifters.h>
#include <anvill/Transforms.h>
#include <glog/logging.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/ReplaceConstant.h>
#include <remill/BC/Util.h>

#include "Utils.h"

namespace anvill {
namespace {

class ConcreteStackPointerResolver final : public NullCrossReferenceResolver {
 private:
  llvm::Module * const module;
  const StackFrameRecoveryOptions &options;

 public:
  virtual ~ConcreteStackPointerResolver(void) = default;

  inline explicit ConcreteStackPointerResolver(
      llvm::Module *module_,
      const StackFrameRecoveryOptions &options_)
      : module(module_), options(options_) {}

  std::optional<std::uint64_t> AddressOfEntity(
        llvm::Constant *ent) const final {
    if (!IsStackPointer(module, ent)) {
      return std::nullopt;
    }

    uint64_t base64 = 0;
    uint64_t base32 = 0;
    uint64_t base16 = 0;
    if (options.stack_pointer_is_negative) {
      base64 = 0xffff7ffc07000000ull;
      base32 = 0xff860000ull;
      base16 = 0xf800ull;
    } else {
      base64 = 0x00007ffc07000000ull;
      base32 = 0x00860000ull;
      base16 = 0x0800ull;
    }

    switch (auto addr_size = module->getDataLayout().getPointerSizeInBits(0)) {
      case 64: return base64;
      case 32: return base32;
      case 16: return base16;
      default:
        LOG(ERROR) << "Unsupported address size " << addr_size;
        return std::nullopt;
    }
  }
};

}  // namespace

// Remove constant expressions of the stack pointer that are not themselves
// resolvable to references. For example, comparisons between one or two
// stack pointer values.
void AddRemoveStackPointerCExprs(llvm::FunctionPassManager &fpm,
                                 const StackFrameRecoveryOptions &options) {
  fpm.addPass(RemoveStackPointerCExprs(options));
}

llvm::StringRef RemoveStackPointerCExprs::name(void) {
  return "RemoveStackPointerCExprs";
}

llvm::PreservedAnalyses
RemoveStackPointerCExprs::run(llvm::Function &func,
                              llvm::FunctionAnalysisManager &fam) {
  if (func.isDeclaration()) {
    return llvm::PreservedAnalyses::all();
  }

  llvm::Module * const module = func.getParent();
  const llvm::DataLayout &dl = module->getDataLayout();
  const auto addr_size = dl.getPointerSizeInBits(0);

  ConcreteStackPointerResolver resolver(module, options);
  CrossReferenceFolder folder(resolver, dl);
  StackPointerResolver stack_resolver(module);

  std::vector<llvm::Instruction *> worklist;

  for (auto &insn : llvm::instructions(func)) {
    worklist.push_back(&insn);
  }

  llvm::Instruction *ce_insert_loc =
      &*func.getEntryBlock().getFirstInsertionPt();

  auto changed = false;
  while (!worklist.empty()) {
    auto curr = worklist.back();
    worklist.pop_back();
    for (llvm::Use &use : curr->operands()) {
      auto ce = llvm::dyn_cast_or_null<llvm::ConstantExpr>(use.get());
      if (!ce) {
        continue;
      }

      if (!stack_resolver.IsRelatedToStackPointer(ce)) {
        continue;
      }

      ResolvedCrossReference xr = folder.TryResolveReferenceWithCaching(ce);
      if (xr.is_valid) {
        if (xr.size < addr_size) {
          if (auto ity = llvm::dyn_cast<llvm::IntegerType>(ce->getType())) {
            auto disp = static_cast<uint64_t>(xr.Displacement(dl));
            use.set(llvm::ConstantInt::get(ity, disp, true));
            changed = true;
            continue;
          }
        }
      } else {

        changed = true;

        // NOTE(ian): convertConstantExprsToInstructions in llvm 14 builds
        //            multiple replacement instructions for components of the
        //            cexpr so we wouldn't need to do this loop the method for
        //            doing this is much better. createReplacementInstr doesn't
        //            work because it tries to translate the whole instruction.
        auto newi = ce->getAsInstruction();
        newi->insertBefore(ce_insert_loc);
        use.set(newi);

        ce_insert_loc = newi;

        worklist.push_back(newi);
      }
    }
  }
  return ConvertBoolToPreserved(changed);
}
}  // namespace anvill
