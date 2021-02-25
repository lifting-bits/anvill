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

#include <anvill/Transforms.h>

#include <llvm/IR/Function.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>

#include <glog/logging.h>

#include "Utils.h"

namespace anvill {
namespace {

class RemoveUnusedFPClassificationCalls final : public llvm::FunctionPass {
 public:

  RemoveUnusedFPClassificationCalls(void)
      : llvm::FunctionPass(ID) {}

  bool runOnFunction(llvm::Function &func) final;

 private:
  static char ID;
};

char RemoveUnusedFPClassificationCalls::ID = '\0';

// Try to lower remill memory access intrinsics.
bool RemoveUnusedFPClassificationCalls::runOnFunction(llvm::Function &func) {
  auto calls = FindFunctionCalls(func, [] (llvm::CallBase *call) -> bool {
    const auto func = call->getCalledFunction();
    if (!func) {
      return false;
    }

    const auto name = func->getName();
    return name == "fpclassify" || name == "__fpclassifyd" ||
           name == "__fpclassifyf" || name == "__fpclassifyld";
  });

  auto ret = false;
  for (llvm::CallBase *call : calls) {
    if (call->use_empty()) {
      call->eraseFromParent();
      ret = true;
    }
  }

  return ret;
}

}  // namespace

// Remove unused calls to floating point classification functions. Calls to
// these functions are present in a bunch of FPU-related instruction semantics
// functions. It's frequently the case that instructions don't actually care
// about the FPU state, though. In these cases, we won't observe the return
// values of these classification functions being used. However, LLVM can't
// eliminate the calls to these functions on its own because they are not
// "pure" functions.
//
// NOTE(pag): This pass must be applied before any kind of renaming of lifted
//            functions is performed, so that we don't accidentally remove
//            calls to classification functions present in the target binary.
llvm::FunctionPass *CreateRemoveUnusedFPClassificationCalls(void) {
  return new RemoveUnusedFPClassificationCalls;
}

}  // namespace anvill
