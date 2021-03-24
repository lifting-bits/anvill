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

#include <anvill/Decl.h>
#include <anvill/Lifters/DeclLifter.h>
#include <glog/logging.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Util.h>

namespace anvill {
namespace {


// Adapt `src` to another type (likely an integer type) that is `dest_type`.
static llvm::Value *AdaptToType(llvm::IRBuilder<> &ir, llvm::Value *src,
                                llvm::Type *dest_type) {
  const auto src_type = src->getType();
  if (src_type == dest_type) {
    return src;
  }

  if (src_type->isIntegerTy()) {
    if (dest_type->isIntegerTy()) {
      auto src_size = src_type->getPrimitiveSizeInBits();
      auto dest_size = dest_type->getPrimitiveSizeInBits();
      if (src_size < dest_size) {
        return ir.CreateZExt(src, dest_type);
      } else {
        return ir.CreateTrunc(src, dest_type);
      }

    } else if (auto dest_ptr_type =
                   llvm::dyn_cast<llvm::PointerType>(dest_type);
               dest_ptr_type) {
      auto inter_type =
          llvm::PointerType::get(dest_ptr_type->getElementType(), 0);

      llvm::Value *inter_val = nullptr;
      if (auto pti = llvm::dyn_cast<llvm::PtrToIntOperator>(src); pti) {
        src = llvm::cast<llvm::Constant>(pti->getOperand(0));
        if (src->getType() == dest_type) {
          return src;
        } else {
          inter_val = ir.CreateBitCast(src, inter_type);
        }

      } else {
        inter_val = ir.CreateIntToPtr(src, inter_type);
      }

      if (inter_type == dest_ptr_type) {
        return inter_val;
      } else {
        return ir.CreateAddrSpaceCast(inter_val, dest_ptr_type);
      }
    }

  } else if (auto src_ptr_type = llvm::dyn_cast<llvm::PointerType>(src_type);
             src_ptr_type) {

    // Cast the pointer to the other pointer type.
    if (auto dest_ptr_type = llvm::dyn_cast<llvm::PointerType>(dest_type);
        dest_ptr_type) {

      if (src_ptr_type->getAddressSpace() != dest_ptr_type->getAddressSpace()) {
        src_ptr_type = llvm::PointerType::get(src_ptr_type->getElementType(),
                                              dest_ptr_type->getAddressSpace());
        src = ir.CreateAddrSpaceCast(src, src_ptr_type);
      }

      if (src_ptr_type == dest_ptr_type) {
        return src;
      } else {
        return ir.CreateBitCast(src, dest_ptr_type);
      }

    // Convert the pointer to an integer.
    } else if (auto dest_int_type =
                   llvm::dyn_cast<llvm::IntegerType>(dest_type);
               dest_int_type) {
      if (src_ptr_type->getAddressSpace()) {
        src_ptr_type =
            llvm::PointerType::get(src_ptr_type->getElementType(), 0);
        src = ir.CreateAddrSpaceCast(src, src_ptr_type);
      }

      const auto block = ir.GetInsertBlock();
      const auto func = block->getParent();
      const auto module = func->getParent();
      const auto &dl = module->getDataLayout();
      auto &context = module->getContext();
      src = ir.CreatePtrToInt(
          src, llvm::Type::getIntNTy(context, dl.getPointerSizeInBits(0)));
      return AdaptToType(ir, src, dest_type);
    }

  } else if (src_type->isFloatTy()) {
    if (dest_type->isDoubleTy()) {
      return ir.CreateFPExt(src, dest_type);

    } else if (dest_type->isIntegerTy()) {
      const auto i32_type = llvm::Type::getInt32Ty(dest_type->getContext());
      return AdaptToType(ir, ir.CreateBitCast(src, i32_type), dest_type);
    }

  } else if (src_type->isDoubleTy()) {
    if (dest_type->isFloatTy()) {
      return ir.CreateFPTrunc(src, dest_type);

    } else if (dest_type->isIntegerTy()) {
      const auto i64_type = llvm::Type::getInt64Ty(dest_type->getContext());
      return AdaptToType(ir, ir.CreateBitCast(src, i64_type), dest_type);
    }
  }

  // Fall-through, we don't have a supported adaptor.
  return nullptr;
}

}  // namespace

// Produce one or more instructions in `in_block` to store the
// native value `native_val` into the lifted state associated
// with `decl`.
llvm::Value *StoreNativeValue(llvm::Value *native_val, const ValueDecl &decl,
                              const remill::IntrinsicTable &intrinsics,
                              llvm::BasicBlock *in_block,
                              llvm::Value *state_ptr, llvm::Value *mem_ptr) {

  auto func = in_block->getParent();
  auto module = func->getParent();

  CHECK_EQ(module, intrinsics.read_memory_8->getParent());
  CHECK_EQ(native_val->getType(), decl.type);

  // Store it to a register.
  if (decl.reg) {
    auto ptr_to_reg = decl.reg->AddressOf(state_ptr, in_block);
    llvm::IRBuilder<> ir(in_block);
    if (decl.type != decl.reg->type) {
      ir.CreateStore(llvm::Constant::getNullValue(decl.reg->type), ptr_to_reg);
    }

    if (auto adapted_val = AdaptToType(ir, native_val, decl.reg->type);
        adapted_val) {
      ir.CreateStore(adapted_val, ptr_to_reg);

    } else {
      ir.CreateStore(
          native_val,
          ir.CreateBitCast(ptr_to_reg, llvm::PointerType::get(decl.type, 0)));
    }

    return mem_ptr;

  // Store it to memory.
  } else if (decl.mem_reg) {
    auto ptr_to_reg = decl.mem_reg->AddressOf(state_ptr, in_block);

    llvm::IRBuilder<> ir(in_block);
    const auto addr = ir.CreateAdd(
        ir.CreateLoad(ptr_to_reg),
        llvm::ConstantInt::get(decl.mem_reg->type,
                               static_cast<uint64_t>(decl.mem_offset), true));
    return remill::StoreToMemory(intrinsics, in_block, native_val, mem_ptr,
                                 addr);

  } else {
    return llvm::UndefValue::get(mem_ptr->getType());
  }
}

llvm::Value *LoadLiftedValue(const ValueDecl &decl,
                             const remill::IntrinsicTable &intrinsics,
                             llvm::BasicBlock *in_block, llvm::Value *state_ptr,
                             llvm::Value *mem_ptr) {

  auto func = in_block->getParent();
  auto module = func->getParent();

  CHECK_EQ(module, intrinsics.read_memory_8->getParent());

  // Load it out of a register.
  if (decl.reg) {
    auto ptr_to_reg = decl.reg->AddressOf(state_ptr, in_block);
    llvm::IRBuilder<> ir(in_block);
    auto reg = ir.CreateLoad(ptr_to_reg);
    if (auto adapted_val = AdaptToType(ir, reg, decl.type)) {
      return adapted_val;
    } else {
      return ir.CreateLoad(
          ir.CreateBitCast(ptr_to_reg, llvm::PointerType::get(decl.type, 0)));
    }

  // Load it out of memory.
  } else if (decl.mem_reg) {
    auto ptr_to_reg = decl.mem_reg->AddressOf(state_ptr, in_block);
    llvm::IRBuilder<> ir(in_block);
    const auto addr = ir.CreateAdd(
        ir.CreateLoad(ptr_to_reg),
        llvm::ConstantInt::get(decl.mem_reg->type,
                               static_cast<uint64_t>(decl.mem_offset), true));
    return llvm::dyn_cast<llvm::Instruction>(
        remill::LoadFromMemory(intrinsics, in_block, decl.type, mem_ptr, addr));

  } else {
    return llvm::UndefValue::get(decl.type);
  }
}

}  // namespace anvill
