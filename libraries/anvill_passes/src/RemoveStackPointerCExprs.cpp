

/*
 * Copyright (c) 2021 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "RemoveStackPointerCExprs.h"

#include <anvill/Analysis/CrossReferenceResolver.h>
#include <anvill/Analysis/Utils.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/ReplaceConstant.h>

#include <iostream>

namespace anvill {

void AddRemoveStackPointerCExprs(llvm::FunctionPassManager &fpm) {
  fpm.addPass(RemoveStackPointerCExprs());
}

llvm::PreservedAnalyses
RemoveStackPointerCExprs::run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM) {
  bool did_see = false;

  CrossReferenceResolver resolver(F.getParent()->getDataLayout());
  std::vector<llvm::Instruction *> worklist;

  for (auto &insn : llvm::instructions(F)) {
    worklist.push_back(&insn);
  }

  did_see = false;
  while (!worklist.empty()) {
    auto curr = worklist.back();
    worklist.pop_back();
    for (auto &use : curr->operands()) {
      if (llvm::isa_and_nonnull<llvm::ConstantExpr>(use.get()) &&
          IsRelatedToStackPointer(F.getParent(), use.get())) {

        auto cexpr = llvm::cast<llvm::ConstantExpr>(use.get());
        auto maybe_resolved =
            resolver.TryResolveReferenceWithClearedCache(cexpr);

        //NOTE(ian): Ok new idea we need to split constant expressions iff they are not resolvable to a stack reference with displacement
        if (!maybe_resolved.is_valid ||
            !maybe_resolved.references_stack_pointer) {

          did_see = true;

          // NOTE(ian): convertConstantExprsToInstructions in llvm 14 builds multiple replacement instructions for components of the cexpr so we wouldnt need to do this loop
          // the method for doing this is much better. createReplacementInstr doesnt work because it tries to translate the whole instruction...
          auto newi = cexpr->getAsInstruction();
          newi->insertBefore(curr);
          use.set(newi);

          worklist.push_back(newi);
        }
      }
    }
  }

  if (did_see) {
    return llvm::PreservedAnalyses::none();
  } else {
    return llvm::PreservedAnalyses::all();
  }
}
}  // namespace anvill