/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Passes/LowerRemillMemoryAccessIntrinsics.h>

#include <anvill/Transforms.h>
#include <glog/logging.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>

#include "Utils.h"

namespace anvill {
namespace {

// Lower a memory read intrinsic into a `load` instruction.
static void ReplaceMemReadOp(llvm::CallBase *call_inst, llvm::Type *val_type) {
  auto addr = call_inst->getArgOperand(1);
  llvm::IRBuilder<> ir(call_inst);
  auto ptr = ir.CreateIntToPtr(addr, llvm::PointerType::get(ir.getContext(), 0));
  CopyMetadataTo(call_inst, ptr);
  llvm::Value *val = ir.CreateLoad(val_type, ptr);
  CopyMetadataTo(call_inst, val);
  if (val_type->isX86_FP80Ty() || val_type->isFP128Ty()) {
    val = ir.CreateFPTrunc(val, call_inst->getType());
    CopyMetadataTo(call_inst, val);
  }
  call_inst->replaceAllUsesWith(val);
  call_inst->eraseFromParent();
}

// Lower a memory read intrinsic with 3 arguments into `load` and
// `store` instructions.
static void ReplaceMemReadOpToRef(llvm::CallBase *call_inst,
                                  llvm::Type *val_type) {
  auto mem_ptr = call_inst->getArgOperand(0);
  auto addr = call_inst->getArgOperand(1);

  llvm::IRBuilder<> ir(call_inst);
  auto ptr = ir.CreateIntToPtr(addr, llvm::PointerType::get(ir.getContext(), 0));
  CopyMetadataTo(call_inst, ptr);
  llvm::Value *val = ir.CreateLoad(val_type, ptr);
  CopyMetadataTo(call_inst, val);

  auto val_ptr = ir.CreateBitCast(call_inst->getArgOperand(2),
                                  llvm::PointerType::get(ir.getContext(), 0));
  CopyMetadataTo(call_inst, val_ptr);
  val = ir.CreateStore(val, val_ptr);
  CopyMetadataTo(call_inst, val);
  call_inst->replaceAllUsesWith(mem_ptr);
  call_inst->eraseFromParent();
}


// Lower a memory write intrinsic into a `store` instruction.
static void ReplaceMemWriteOp(llvm::CallBase *call_inst, llvm::Type *val_type) {
  auto mem_ptr = call_inst->getArgOperand(0);
  auto addr = call_inst->getArgOperand(1);
  auto val = call_inst->getArgOperand(2);

  llvm::IRBuilder<> ir(call_inst);
  auto ptr = ir.CreateIntToPtr(addr, llvm::PointerType::get(ir.getContext(), 0));
  CopyMetadataTo(call_inst, ptr);
  if (val_type->isX86_FP80Ty() || val_type->isFP128Ty()) {
    val = ir.CreateFPExt(val, val_type);
    CopyMetadataTo(call_inst, val);
  }

  val = ir.CreateStore(val, ptr);
  CopyMetadataTo(call_inst, val);
  call_inst->replaceAllUsesWith(mem_ptr);
  call_inst->eraseFromParent();
}

// Lower a memory write intrinsic passing value by reference with `store`
// instruction
static void ReplaceMemWriteOpFromRef(llvm::CallBase *call_inst,
                                     llvm::Type *val_type) {
  auto mem_ptr = call_inst->getArgOperand(0);
  auto addr = call_inst->getArgOperand(1);
  auto val_ptr = call_inst->getArgOperand(2);

  llvm::IRBuilder<> ir(call_inst);
  auto ptr = ir.CreateIntToPtr(addr, llvm::PointerType::get(ir.getContext(), 0));
  CopyMetadataTo(call_inst, ptr);

  llvm::Value *val = ir.CreateLoad(val_type, val_ptr);
  if (val_type->isX86_FP80Ty() || val_type->isFP128Ty()) {
    val = ir.CreateFPExt(val, val_type);
    CopyMetadataTo(call_inst, val);
  }

  val = ir.CreateStore(val, ptr);
  CopyMetadataTo(call_inst, val);
  call_inst->replaceAllUsesWith(mem_ptr);
  call_inst->eraseFromParent();
}

// Dispatch to the proper memory replacement function given a function call.
static bool ReplaceMemoryOp(llvm::CallBase *call) {
  const auto func = call->getCalledFunction();
  const auto func_name = func->getName();

  // Perform a value type adjustment. Remill re-interprets loads/stores of
  // extended precision and quad precision floating point values as operating
  // on double precision floats, then opaquely performing the necessary
  // conversions at the memory boundary.
  auto adjust_val_type = [=](llvm::Type *val_type) -> llvm::Type * {
    auto &context = val_type->getContext();
    if (func_name.endswith("f80")) {
      return llvm::Type::getX86_FP80Ty(context);
    } else if (func_name.endswith("f128")) {
      return llvm::Type::getFP128Ty(context);
    } else {
      return val_type;
    }
  };


  if (func_name.startswith("__remill_read_memory_")) {
    switch (call->getNumArgOperands()) {

      // `val = __remill_read_memory_NN(mem, addr)`.
      case 2: {
        const auto val_type = adjust_val_type(call->getType());
        ReplaceMemReadOp(call, val_type);
        return true;
      }

      // `mem = __remill_read_memory_NN(mem, addr, val&)`.
      case 3: {
        const auto val_type =
            adjust_val_type(call->getArgOperand(2)->getType());
        ReplaceMemReadOpToRef(call, val_type);
        return true;
      }
      default:
        LOG(ERROR) << "Missing support for lowering memory read operation "
                   << func_name.str();
        return false;
    }

  } else if (func_name.startswith("__remill_write_memory_")) {
    auto arg3_type = call->getArgOperand(2)->getType();

    // `mem = __remill_write_memory_NN(mem, addr, val&)`.
    if (llvm::isa<llvm::PointerType>(arg3_type)) {
      const auto val_type = adjust_val_type(arg3_type);
      ReplaceMemWriteOpFromRef(call, val_type);
      return true;

      // `mem = __remill_write_memory_NN(mem, addr, val)`.
    } else {
      const auto val_type = adjust_val_type(arg3_type);
      ReplaceMemWriteOp(call, val_type);
      return true;
    }
  }

  LOG(ERROR) << "Missing support for lowering memory operation "
             << func_name.str();
  return false;
}

}  // namespace

llvm::StringRef LowerRemillMemoryAccessIntrinsics::name(void) {
  return "LowerRemillMemoryAccessIntrinsics";
}

// Try to lower remill memory access intrinsics.
llvm::PreservedAnalyses
LowerRemillMemoryAccessIntrinsics::run(llvm::Function &func,
                                       llvm::FunctionAnalysisManager &AM) {
  auto calls = FindFunctionCalls(func, [](llvm::CallBase *call) -> bool {
    const auto func = call->getCalledFunction();
    if (!func) {
      return false;
    }

    // TODO(pag): Add support for atomic read-modify-write intrinsics.
    const auto name = func->getName();
    return name.startswith("__remill_read_memory_") ||
           name.startswith("__remill_write_memory_");
  });

  auto ret = false;
  for (auto call : calls) {
    ret = ReplaceMemoryOp(call) || ret;
  }

  return ConvertBoolToPreserved(ret);
}

// Lowers the `__remill_read_memory_NN`, `__remill_write_memory_NN`, and the
// various atomic read-modify-write variants into LLVM loads and stores.
void AddLowerRemillMemoryAccessIntrinsics(llvm::FunctionPassManager &fpm) {
  fpm.addPass(LowerRemillMemoryAccessIntrinsics());
}

}  // namespace anvill
