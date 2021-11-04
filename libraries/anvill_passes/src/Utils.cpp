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

#include "Utils.h"

#include <glog/logging.h>
#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
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
      const auto new_ptr_ty = ptr_ty->getElementType()->getPointerTo(
          dest_ptr_ty->getAddressSpace());
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
    if (int_ty->getPrimitiveSizeInBits().getKnownMinSize() < pointer_width) {
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
      const auto new_ptr_ty = ptr_ty->getElementType()->getPointerTo(
          dest_ptr_ty->getAddressSpace());
      val_to_convert = ir.CreateAddrSpaceCast(val_to_convert, new_ptr_ty);
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
    if (int_ty->getPrimitiveSizeInBits().getKnownMinSize() < pointer_width) {
      int_ty =
          llvm::Type::getIntNTy(val_to_convert->getContext(), pointer_width);
      val_to_convert = ir.CreateZExt(val_to_convert, int_ty);
    }

    return ir.CreateIntToPtr(val_to_convert, dest_ptr_ty);

  } else {
    return ir.CreateBitOrPointerCast(val_to_convert, dest_ptr_ty);
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

void CopyMetadataTo(llvm::Value *src, llvm::Value *dst) {
  llvm::Instruction *src_inst = llvm::dyn_cast_or_null<llvm::Instruction>(src),
                    *dst_inst = llvm::dyn_cast_or_null<llvm::Instruction>(dst);
  if (src_inst && dst_inst) {
    dst_inst->copyMetadata(*src_inst);
  }
}


llvm::PreservedAnalyses ConvertBoolToPreserved(bool modified) {
  return modified ? llvm::PreservedAnalyses::none()
                  : llvm::PreservedAnalyses::all();
}
}  // namespace anvill
