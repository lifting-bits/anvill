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
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/Pass.h>

#include <remill/BC/ABI.h>
#include <remill/BC/Util.h>

#include <glog/logging.h>

#include <utility>
#include <vector>

namespace anvill {
namespace {

class RemoveRemillFunctionReturns final : public llvm::FunctionPass {
 public:

  RemoveRemillFunctionReturns(void)
      : llvm::FunctionPass(ID) {}

  bool runOnFunction(llvm::Function &func) final;

 private:
  static char ID;
};

char RemoveRemillFunctionReturns::ID = '\0';

enum ReturnAddressResult {
  kFoundReturnAddress,
  kFoundSymbolicStackPointerLoad,
  kUnclassifiableReturnAddress
};

static bool IsRelatedToStackPointer(llvm::Value *val) {
  return true;
}

// Returns `true` if `val` is a return address.
static ReturnAddressResult QueryReturnAddress(llvm::Value *val) {
  if (auto call = llvm::dyn_cast<llvm::CallBase>(val)) {
    if (call->getIntrinsicID() == llvm::Intrinsic::returnaddress) {
      return kFoundReturnAddress;
    } else if (auto func = call->getCalledFunction()) {
      if (func->getName().startswith("__remill_read_memory_")) {
        auto addr = call->getArgOperand(1);  // Address
        if (IsRelatedToStackPointer(addr)) {
          return kFoundSymbolicStackPointerLoad;
        } else {
          return kUnclassifiableReturnAddress;
        }
      }
    }
    return kUnclassifiableReturnAddress;

  } else if (auto li = llvm::dyn_cast<llvm::LoadInst>(val)) {
    if (IsRelatedToStackPointer(li->getPointerOperand())) {
      return kFoundSymbolicStackPointerLoad;
    } else {
      return kUnclassifiableReturnAddress;
    }

  } else if (auto gv = llvm::dyn_cast<llvm::GlobalVariable>(val)) {
    if (gv->getName() == "__anvill_ra") {
      return kFoundReturnAddress;
    } else {
      return kUnclassifiableReturnAddress;
    }

  } else if (auto pti = llvm::dyn_cast<llvm::PtrToIntOperator>(val)) {
    return QueryReturnAddress(pti->getOperand(0));

  } else if (auto cast = llvm::dyn_cast<llvm::CastInst>(val)) {
    return QueryReturnAddress(cast->getOperand(0));

  } else {
    return kUnclassifiableReturnAddress;
  }
}

// Try to identify the patterns of `__remill_function_call` that we can
// remove.
bool RemoveRemillFunctionReturns::runOnFunction(llvm::Function &func) {

  std::vector<llvm::CallBase *> matches_pattern;

  for (auto &inst : llvm::instructions(func)) {
    if (auto call = llvm::dyn_cast<llvm::CallBase>(&inst)) {
      if (auto func = call->getCalledFunction();
          func && func->getName() == "__remill_function_return") {
        auto ret_addr = call->getArgOperand(remill::kPCArgNum)
                            ->stripPointerCastsAndAliases();
        switch (QueryReturnAddress(ret_addr)) {
          case kFoundReturnAddress:
            matches_pattern.push_back(call);
            break;

          // Do nothing if it's a symbolic stack pointer load; we're probably
          // running this pass too early.
          case kFoundSymbolicStackPointerLoad:
            break;

          // Here we'll do an arch-specific fixup.
          case kUnclassifiableReturnAddress:
            break;
        }
      }
    }
  }

  // Go remove all the matches that we can.
  for (auto call : matches_pattern) {
    auto ret_addr = llvm::dyn_cast<llvm::Instruction>(
        call->getArgOperand(remill::kPCArgNum));
    auto mem_ptr = call->getArgOperand(remill::kMemoryPointerArgNum);
    call->replaceAllUsesWith(mem_ptr);
    call->eraseFromParent();

    // Work up the use list of casts back to the source of this return
    // address, eliminating as many of those values as possible.
    while (ret_addr && ret_addr->use_empty()) {

      // Cast of `llvm.returnaddress`.
      if (auto cast_inst = llvm::dyn_cast<llvm::CastInst>(ret_addr)) {
        auto next_ret_addr = llvm::dyn_cast<llvm::Instruction>(
            cast_inst->getOperand(0));
        ret_addr->eraseFromParent();
        ret_addr = next_ret_addr;

      // Call to `llvm.returnaddress`.
      } else if (auto call_inst = llvm::dyn_cast<llvm::CallBase>(ret_addr)) {
        if (call_inst->getIntrinsicID() == llvm::Intrinsic::returnaddress) {
          call_inst->eraseFromParent();
        }
        break;

      // Who knows?!
      } else {
        LOG(ERROR)
            << "Encountered unexpected instruction when removing return address: "
            << remill::LLVMThingToString(ret_addr);
        break;
      }
    }
  }

  return !matches_pattern.empty();
}

}  // namespace

// Transforms the bitcode to eliminate calls to `__remill_function_return`,
// where appropriate. This will not succeed for all architectures, but is
// likely to always succeed for x86(-64) and aarch64, due to their support
// for the `llvm.addressofreturnaddress` intrinsic.
//
// When we lift bitcode, we represent the control-flow transfer semantics of
// function returns with calls to `__remill_function_return`. This is another
// three-argument Remill function, where the second argument is the program
// counter. We're particularly interested in observing this program counter
// value, as it can tell us if this function respects normal return conventions
// (i.e. returns to its return address) or not. The way we try to observe this
// is by inspecting the program counter argument, and seeing if it is
// `__anvill_ra` or the (casted) value returned from the `llvm.returnaddress`
// intrinsic.
//
// When we match the expected pattern, we can eliminate calls to
// `__remill_function_return`. If we don't match the pattern, then it suggests
// that it is possible that the function alters its return address, or that
// something is preventing our analysis from deducing that the return address
// reaches the `__remill_function_return` call's program counter argument.
//
// On x86(-64) and AArch64, we can use the `llvm.addressofreturnaddress` to
// update the return address in place when we fail to match the pattern,
// thereby letting us eliminate the call to `__remill_function_return`.
//
// NOTE(pag): This pass should be applied as late as possible, as the call to
//            `__remill_function_return` depends upon the memory pointer.
llvm::FunctionPass *CreateRemoveRemillFunctionReturns(void) {
  return new RemoveRemillFunctionReturns;
}

}  // namespace anvill
