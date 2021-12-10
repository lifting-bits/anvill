/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Passes/SpreadPCMetadata.h>

#include <anvill/Lifters.h>
#include <anvill/Transforms.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>

#include "Utils.h"

namespace anvill {

llvm::PreservedAnalyses SpreadPCMetadata::run(
    llvm::Function &func, llvm::FunctionAnalysisManager &fam) {

  llvm::LLVMContext &context = func.getContext();
  auto md_id = context.getMDKindID(pc_metadata_name);
  auto changed = false;

  for (llvm::BasicBlock &block : func) {

    auto has_missing = false;
    llvm::MDNode *last_md = nullptr;
    for (llvm::Instruction &inst : block) {
      auto md = inst.getMetadata(md_id);
      if (!md) {
        has_missing = true;
        continue;
      }

      last_md = md;

      // Propagate the pc metadata of an instruction back to its uses, if those
      // uses are in the same block.
      for (llvm::Use &op : inst.operands()) {
        if (auto inst_arg = llvm::dyn_cast<llvm::Instruction>(op.get());
            inst_arg && inst_arg->getParent() == &block) {
          if (!inst_arg->getMetadata(md_id)) {
            inst_arg->setMetadata(md_id, md);
            changed = true;
          }
        }
      }
    }

    if (!has_missing) {
      continue;
    }

    // Go backward through the basic block and apply any known metadata IDs to
    // instructions.
    auto rit = block.rbegin();
    auto rend = block.rend();
    for (; rit != rend; ++rit) {
      llvm::Instruction &inst = *rit;
      if (auto md = inst.getMetadata(md_id)) {
        last_md = md;
      } else if (last_md) {
        inst.setMetadata(md_id, last_md);
        changed = true;
      }
    }
  }

  return ConvertBoolToPreserved(changed);
}

llvm::StringRef SpreadPCMetadata::name(void) {
  return "SpreadPCMetadata";
}

// Looks for instructions missing the program counter-specific metadata, and
// spreads nearby program counter-annotated metadata to those instructions.
void AddSpreadPCMetadata(llvm::FunctionPassManager &fpm,
                         const LifterOptions &options) {
  if (options.pc_metadata_name) {
    fpm.addPass(SpreadPCMetadata(options.pc_metadata_name));
  }
}

}  // namespace anvill
