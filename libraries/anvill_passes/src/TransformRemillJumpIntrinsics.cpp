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

#include <anvill/Analysis/CrossReferenceResolver.h>
#include <anvill/Analysis/Utils.h>
#include <anvill/Lifters/EntityLifter.h>
#include <anvill/Transforms.h>
#include <glog/logging.h>
#include <llvm/ADT/Triple.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Util.h>

#include <utility>
#include <vector>


namespace anvill {
namespace {

const std::string_view remill_jump = "__remill_jump";
const std::string_view remill_function_return = "__remill_function_return";

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

class TransformRemillJumpIntrinsics final : public llvm::FunctionPass {
 public:
  TransformRemillJumpIntrinsics(const EntityLifter &lifter_)
      : llvm::FunctionPass(ID),
        xref_resolver_(lifter_) {}

  bool runOnFunction(llvm::Function &func) final;

 private:
  ReturnAddressResult QueryReturnAddress(const llvm::DataLayout &dl,
                                         llvm::Value *val) const;

  bool TransformJumpIntrinsic(llvm::CallBase *call);

  static char ID;
  const CrossReferenceResolver xref_resolver_;
};


char TransformRemillJumpIntrinsics::ID = '\0';

// Returns `true` if `val` is a possible return address
ReturnAddressResult
TransformRemillJumpIntrinsics::QueryReturnAddress(const llvm::DataLayout &dl,
                                                  llvm::Value *val) const {

  if (auto call = llvm::dyn_cast<llvm::CallBase>(val)) {
    if (call->getIntrinsicID() == llvm::Intrinsic::returnaddress) {
      return kReturnAddressProgramCounter;
    } else if (auto func = call->getCalledFunction()) {
      if (func->getName().startswith("__remill_read_memory_")) {
        auto addr = call->getArgOperand(1);  // Address

        // Could it be address of return address ??
        auto addr_of_ret = llvm::dyn_cast<llvm::CallBase>(addr);
        if (addr_of_ret->getIntrinsicID() ==
            llvm::Intrinsic::addressofreturnaddress) {
          return kReturnAddressProgramCounter;
        }
      }
    }

  } else if (auto gv = llvm::dyn_cast<llvm::GlobalVariable>(val);
             gv && IsReturnAddress(gv)) {
    return kReturnAddressProgramCounter;

  } else if (auto pti = llvm::dyn_cast<llvm::PtrToIntOperator>(val)) {
    return QueryReturnAddress(dl, pti->getOperand(0));

  // Sometimes optimizations result in really crazy looking constant expressions
  // related to `__anvill_ra`, full of shifts, zexts, etc. We try to detect
  // this situation by initializing a "magic" address associated with
  // `__anvill_ra`, and then if we find this magic value on something that
  // references `__anvill_ra`, then we conclude that all those manipulations
  // in the constant expression are actually not important.
  } else if (auto xr = xref_resolver_.TryResolveReference(val);
             xr.is_valid && xr.references_return_address &&
             xr.u.address == xref_resolver_.MagicReturnAddressValue()) {
    return kReturnAddressProgramCounter;
  }

  return kUnclassifiableProgramCounter;
}

// Find the remill intrinsic in module. If it is missing create one
// with the given function type
static llvm::Function *FindIntrinsic(llvm::Module *module,
                                     llvm::FunctionType *type,
                                     const char *name) {
  auto function = module->getFunction(name);
  if (!function) {
    function = llvm::Function::Create(type, llvm::GlobalValue::ExternalLinkage,
                                      name, module);
  }

  CHECK(nullptr != function) << "Unable to get intrinsic: " << name;
  function->addFnAttr(llvm::Attribute::NoDuplicate);
  function->addFnAttr(llvm::Attribute::NoUnwind);
  function->addFnAttr(llvm::Attribute::OptimizeNone);
  function->addFnAttr(llvm::Attribute::NoInline);
  function->removeFnAttr(llvm::Attribute::NoReturn);
  function->removeFnAttr(llvm::Attribute::UWTable);
  function->removeFnAttr(llvm::Attribute::AlwaysInline);
  return function;
}

// Find the call site of the given function and add them to vector
// if `pred(call)` is true
static std::vector<llvm::CallBase *>
FindFunctionCalls(llvm::Function &func,
                  std::function<bool(llvm::CallBase *)> pred) {
  std::vector<llvm::CallBase *> found;
  for (auto &inst : llvm::instructions(func)) {
    if (auto call = llvm::dyn_cast<llvm::CallBase>(&inst); call && pred(call)) {
      found.push_back(call);
    }
  }
  return found;
}

// Dispatch to the proper memory replacement function given a function call.
bool TransformRemillJumpIntrinsics::TransformJumpIntrinsic(
    llvm::CallBase *call) {
  const auto func = call->getCalledFunction();
  const auto module = func->getParent();
  bool func_replaced = false;

  const auto called_func = call->getCalledFunction();
  if (called_func && called_func->getName() == remill_jump.data()) {
    auto func_type = call->getCalledFunction()->getFunctionType();
    auto intrinsic =
        FindIntrinsic(module, func_type, remill_function_return.data());
    call->setCalledOperand(intrinsic);

    // if the called function has no uses delete them
    if (called_func->use_empty()) {
      called_func->eraseFromParent();
    }

    func_replaced = true;
  }

  return func_replaced;
}


// Try to identify the patterns of `__remill_function_call` that we can
// remove.
bool TransformRemillJumpIntrinsics::runOnFunction(llvm::Function &func) {
  const auto module = func.getParent();
  const auto &dl = module->getDataLayout();
  auto calls = FindFunctionCalls(func, [&](llvm::CallBase *call) -> bool {
    const auto func = call->getCalledFunction();
    if (!func || !(func->getName() == remill_jump.data())) {
      return false;
    }

    const auto ret_addr =
        call->getArgOperand(remill::kPCArgNum)->stripPointerCastsAndAliases();
    switch (QueryReturnAddress(dl, ret_addr)) {
      case kReturnAddressProgramCounter: return true;
      case kUnclassifiableProgramCounter: return false;
    }
  });

  auto ret = false;
  for (auto call : calls) {
    ret = TransformJumpIntrinsic(call) || ret;
  }

  return ret;
}

}  // namespace


// The pass transforms bitcode to replace the calls to `__remill_jump` into
// `__remill_function_return` if a value returned by `llvm.returnaddress`, or
// casted from `__anvill_ra`, reaches to its `PC` argument.
//
// The transform is written to fix the bitcode generated for aarch32 architecture
// where multiple instructions semantic can be used to return from the function
// and they might be categorized as (conditional/unconditional) indirect jumps
//
// It identifies the possible cases where a return instruction is lifted as
// indirect jump and fixes the intrinsics for them. The pass should be run before
// `RemoveRemillFunctionReturns` and as late as possible in the list

llvm::FunctionPass *
CreateTransformRemillJumpIntrinsics(const EntityLifter &lifter) {
  return new TransformRemillJumpIntrinsics(lifter);
}

}  // namespace anvill
