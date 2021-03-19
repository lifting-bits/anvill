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

#include <anvill/ABI.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include <vector>

namespace anvill {
namespace {

class LowerTypeHintIntrinsics final : public llvm::FunctionPass {
 public:
  LowerTypeHintIntrinsics(void)
      : llvm::FunctionPass(ID) {}

  bool runOnFunction(llvm::Function &func) override;

 private:
  static char ID;
};

char LowerTypeHintIntrinsics::ID = '\0';

bool LowerTypeHintIntrinsics::runOnFunction(llvm::Function &func) {
  std::vector<llvm::CallInst *> calls;

  for (auto &inst : llvm::instructions(func)) {
    if (auto call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
      if (auto callee = call->getCalledFunction();
          callee && callee->getName().startswith(kTypeHintFunctionPrefix)) {
        calls.push_back(call);
      }
    }
  }

  auto changed = false;
  for (auto call : calls) {
    auto val = call->getArgOperand(0)->stripPointerCasts();
    llvm::IRBuilder<> ir(call);
    call->replaceAllUsesWith(
        ir.CreateBitOrPointerCast(val, call->getType()));
    changed = true;
  }

  for (auto call : calls) {
    if (call->use_empty()) {
      call->eraseFromParent();
      changed = true;
    }
  }

  return changed;
}

}  // namespace

// Type information from prior lifting efforts, or from front-end tools
// (e.g. Binary Ninja) is plumbed through the system by way of calls to
// intrinsic functions such as `__anvill_type<blah>`. These function calls
// don't interfere (too much) with optimizations, and they also survive
// optimizations. In general, the key role that they serve is to enable us to
// propagate through pointer type information at an instruction/register
// granularity.
//
// These function calls need to be removed/lowered into `inttoptr` or `bitcast`
// instructions.
llvm::FunctionPass *CreateLowerTypeHintIntrinsics(void) {
  return new LowerTypeHintIntrinsics;
}

}  // namespace anvill
