/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "Utils.h"

#include <anvill/ABI.h>
#include <glog/logging.h>
#include <llvm/ADT/ArrayRef.h>
#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/TargetParser/Triple.h>
#include <remill/BC/Util.h>

namespace anvill {

// Find all function calls in `func` such that `pred(call)` returns `true`.
std::vector<llvm::CallBase *>
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

namespace {

// Convert the constant `val` to have the pointer type `dest_ptr_ty`.
llvm::Value *ConvertConstantToPointer(llvm::IRBuilder<> &ir,
                                      const llvm::DataLayout &dl,
                                      llvm::Constant *val_to_convert,
                                      llvm::PointerType *dest_ptr_ty) {
  const auto type = val_to_convert->getType();

  // Cast a pointer to a pointer type.
  if (auto ptr_ty = llvm::dyn_cast<llvm::PointerType>(type)) {
    if (ptr_ty->getAddressSpace() != dest_ptr_ty->getAddressSpace()) {
      const auto new_ptr_ty = llvm::PointerType::get(
          ir.getContext(), dest_ptr_ty->getAddressSpace());
      val_to_convert =
          llvm::ConstantExpr::getAddrSpaceCast(val_to_convert, new_ptr_ty);
      ptr_ty = new_ptr_ty;
    }

    if (ptr_ty == dest_ptr_ty) {
      return val_to_convert;

    } else {
      return remill::BuildPointerToOffset(ir, val_to_convert, 0, dest_ptr_ty);
    }

    // Cast an integer to a pointer type.
  } else if (auto int_ty = llvm::dyn_cast<llvm::IntegerType>(type)) {
    const auto pointer_width = dl.getPointerTypeSizeInBits(dest_ptr_ty);
    if (int_ty->getPrimitiveSizeInBits().getKnownMinValue() < pointer_width) {
      int_ty =
          llvm::Type::getIntNTy(val_to_convert->getContext(), pointer_width);
      val_to_convert = llvm::ConstantExpr::getZExt(val_to_convert, int_ty);
    }

    return llvm::ConstantExpr::getIntToPtr(val_to_convert, dest_ptr_ty);

  } else {
    LOG(ERROR) << "Unanticipated conversion from "
               << remill::LLVMThingToString(type) << " to "
               << remill::LLVMThingToString(dest_ptr_ty);
    return llvm::ConstantExpr::getBitCast(val_to_convert, dest_ptr_ty);
  }
}


// Convert the constant `val` to have the pointer type `dest_ptr_ty`.
llvm::Value *ConvertValueToPointer(llvm::IRBuilder<> &ir,
                                   const llvm::DataLayout &dl,
                                   llvm::Value *val_to_convert,
                                   llvm::PointerType *dest_ptr_ty) {
  const auto type = val_to_convert->getType();

  // Cast a pointer to a pointer type.
  if (auto ptr_ty = llvm::dyn_cast<llvm::PointerType>(type)) {
    if (ptr_ty->getAddressSpace() != dest_ptr_ty->getAddressSpace()) {
      const auto new_ptr_ty = llvm::PointerType::get(
          ir.getContext(), dest_ptr_ty->getAddressSpace());
      auto dest = ir.CreateAddrSpaceCast(val_to_convert, new_ptr_ty);
      CopyMetadataTo(val_to_convert, dest);
      val_to_convert = dest;
      ptr_ty = new_ptr_ty;
    }

    if (ptr_ty == dest_ptr_ty) {
      return val_to_convert;

    } else {
      auto dest =
          remill::BuildPointerToOffset(ir, val_to_convert, 0, dest_ptr_ty);
      CopyMetadataTo(val_to_convert, dest);
      return dest;
    }

    // Cast an integer to a pointer type.
  } else if (auto int_ty = llvm::dyn_cast<llvm::IntegerType>(type)) {
    const auto pointer_width = dl.getPointerTypeSizeInBits(dest_ptr_ty);
    if (int_ty->getPrimitiveSizeInBits().getKnownMinValue() < pointer_width) {
      int_ty =
          llvm::Type::getIntNTy(val_to_convert->getContext(), pointer_width);
      auto dest = ir.CreateZExt(val_to_convert, int_ty);
      CopyMetadataTo(val_to_convert, dest);
      val_to_convert = dest;
    }

    auto dest = ir.CreateIntToPtr(val_to_convert, dest_ptr_ty);
    CopyMetadataTo(val_to_convert, dest);
    return dest;

  } else {
    auto dest = ir.CreateBitOrPointerCast(val_to_convert, dest_ptr_ty);
    CopyMetadataTo(val_to_convert, dest);
    return dest;
  }
}

}  // namespace

// Convert the constant `val` to have the pointer type `dest_ptr_ty`.
llvm::Value *ConvertToPointer(llvm::Instruction *usage_site,
                              llvm::Value *val_to_convert,
                              llvm::PointerType *dest_ptr_ty) {

  llvm::IRBuilder<> ir(usage_site);
  const auto &dl = usage_site->getModule()->getDataLayout();
  if (auto cv = llvm::dyn_cast<llvm::Constant>(val_to_convert)) {
    return ConvertConstantToPointer(ir, dl, cv, dest_ptr_ty);
  } else {
    return ConvertValueToPointer(ir, dl, val_to_convert, dest_ptr_ty);
  }
}

// Returns the function's IR
std::string GetFunctionIR(llvm::Function &func) {
  std::string output;

  llvm::raw_string_ostream output_stream(output);
  func.print(output_stream, nullptr);

  return output;
}

std::string GetModuleIR(llvm::Module &module) {
  std::string output;

  llvm::raw_string_ostream output_stream(output);
  module.print(output_stream, nullptr);
  output_stream.flush();

  return output;
}

bool BasicBlockIsSane(llvm::BasicBlock *block) {
  bool in_phis = true;
  for (auto &inst : *block) {
    if (llvm::isa<llvm::PHINode>(&inst)) {
      if (!in_phis) {
        DLOG(ERROR) << "Found " << remill::LLVMThingToString(&inst) << " after "
                    << remill::LLVMThingToString(inst.getPrevNode());
        return false;
      }
    } else {
      in_phis = false;
    }
  }
  return true;
}


llvm::PreservedAnalyses ConvertBoolToPreserved(bool modified) {
  return modified ? llvm::PreservedAnalyses::none()
                  : llvm::PreservedAnalyses::all();
}

// Returns the pointer to the function that lets us overwrite the return
// address. This is not available on all architectures / OSes.
llvm::Function *AddressOfReturnAddressFunction(llvm::Module *module) {
  llvm::Triple triple(module->getTargetTriple());
  const char *func_name = nullptr;
  switch (triple.getArch()) {
    case llvm::Triple::ArchType::x86:
    case llvm::Triple::ArchType::x86_64:
    case llvm::Triple::ArchType::aarch64:
    case llvm::Triple::ArchType::aarch64_be:
      func_name = "llvm.addressofreturnaddress.p0";
      break;

    // The Windows `_AddressOfReturnAddress` intrinsic function works on
    // AArch32 / ARMv7 (as well as the above).
    case llvm::Triple::ArchType::arm:
    case llvm::Triple::ArchType::armeb:
    case llvm::Triple::ArchType::aarch64_32:
      if (triple.isOSWindows()) {
        func_name = "_AddressOfReturnAddress";
      }
      break;
    default: break;
  }

  llvm::Function *func = nullptr;

  // Common path to handle the Windows-specific case, or the slightly
  // more general case uniformly.
  if (func_name) {
    func = module->getFunction(func_name);
    if (!func) {
      auto &context = module->getContext();
      auto fty =
          llvm::FunctionType::get(llvm::Type::getInt8PtrTy(context, 0), false);
      func = llvm::Function::Create(fty, llvm::GlobalValue::ExternalLinkage,
                                    func_name, module);
    }
  }

  return func;
}

llvm::Function *GetOrCreateAnvillReturnFunc(llvm::Module *mod) {
  auto tgt_type =
      llvm::FunctionType::get(llvm::Type::getVoidTy(mod->getContext()), true);
  if (auto res = mod->getFunction(anvill::kAnvillBasicBlockReturn)) {
    return res;
  }


  return llvm::Function::Create(tgt_type, llvm::GlobalValue::ExternalLinkage,
                                anvill::kAnvillBasicBlockReturn, mod);
}

std::optional<llvm::ReturnInst *> UniqueReturn(llvm::Function *func) {
  std::optional<llvm::ReturnInst *> r = std::nullopt;
  for (auto &insn : llvm::instructions(func)) {
    if (auto nret = llvm::dyn_cast<llvm::ReturnInst>(&insn)) {
      if (r) {
        return std::nullopt;
      } else {
        r = nret;
      }
    }
  }

  return r;
}

}  // namespace anvill
