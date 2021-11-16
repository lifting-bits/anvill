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

#include <glog/logging.h>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include <anvill/Lifters/DeclLifter.h>
#include <anvill/Type.h>
#include <anvill/Util.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Util.h>

namespace anvill {
namespace {

}  // namespace

// Produce one or more instructions in `in_block` to store the
// native value `native_val` into the lifted state associated
// with `decl`.
llvm::Value *StoreNativeValue(llvm::Value *native_val, const ValueDecl &decl,
                              const TypeDictionary &types,
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

    llvm::StoreInst *store = nullptr;

    auto ipoint = ir.GetInsertPoint();
    auto iblock = ir.GetInsertBlock();
    auto adapted_val = types.ConvertValueToType(ir, native_val, decl.reg->type);
    ir.SetInsertPoint(iblock, ipoint);

    if (adapted_val) {
      store = ir.CreateStore(adapted_val, ptr_to_reg);

    } else {
      auto ptr = ir.CreateBitCast(ptr_to_reg,
                                  llvm::PointerType::get(decl.type, 0));
      CopyMetadataTo(native_val, ptr);
      store = ir.CreateStore(native_val, ptr);
    }
    CopyMetadataTo(native_val, store);

    return mem_ptr;

  // Store it to memory.
  } else if (decl.mem_reg) {
    auto ptr_to_reg = decl.mem_reg->AddressOf(state_ptr, in_block);

    llvm::IRBuilder<> ir(in_block);
    llvm::Value *addr = ir.CreateLoad(decl.mem_reg->type, ptr_to_reg);
    CopyMetadataTo(native_val, addr);

    if (0ll < decl.mem_offset) {
      addr = ir.CreateAdd(
          addr,
          llvm::ConstantInt::get(
              decl.mem_reg->type, static_cast<uint64_t>(decl.mem_offset),
              false));
      CopyMetadataTo(native_val, addr);

    } else if (0ll > decl.mem_offset) {
      addr = ir.CreateSub(
        addr,
        llvm::ConstantInt::get(
            decl.mem_reg->type, static_cast<uint64_t>(-decl.mem_offset),
            false));
      CopyMetadataTo(native_val, addr);
    }

    return remill::StoreToMemory(intrinsics, in_block, native_val, mem_ptr,
                                 addr);

  // Store to memory at an absolute offset.
  } else if (decl.mem_offset) {
    llvm::IRBuilder<> ir(in_block);
    const auto addr = llvm::ConstantInt::get(
        remill::NthArgument(intrinsics.read_memory_8, 1u)->getType(),
        static_cast<uint64_t>(decl.mem_offset), false);
    return remill::StoreToMemory(intrinsics, in_block, native_val, mem_ptr,
                                 addr);

  } else {
    return llvm::UndefValue::get(mem_ptr->getType());
  }
}

llvm::Value *LoadLiftedValue(const ValueDecl &decl,
                             const TypeDictionary &types,
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
    auto reg = ir.CreateLoad(decl.reg->type, ptr_to_reg);
    CopyMetadataTo(mem_ptr, reg);
    auto ipoint = ir.GetInsertPoint();
    auto iblock = ir.GetInsertBlock();
    auto adapted_val = types.ConvertValueToType(ir, reg, decl.type);
    ir.SetInsertPoint(iblock, ipoint);

    if (adapted_val) {
      return adapted_val;
    } else {
      auto bc = ir.CreateBitCast(ptr_to_reg, llvm::PointerType::get(decl.type, 0));
      auto li = ir.CreateLoad(decl.type, bc);
      CopyMetadataTo(mem_ptr, bc);
      CopyMetadataTo(mem_ptr, li);
      return li;
    }

  // Load it out of memory.
  } else if (decl.mem_reg) {
    auto ptr_to_reg = decl.mem_reg->AddressOf(state_ptr, in_block);
    llvm::IRBuilder<> ir(in_block);
    llvm::Value *addr = ir.CreateLoad(decl.mem_reg->type, ptr_to_reg);
    CopyMetadataTo(mem_ptr, addr);
    if (0ll < decl.mem_offset) {
      addr = ir.CreateAdd(
          addr,
          llvm::ConstantInt::get(
              decl.mem_reg->type, static_cast<uint64_t>(decl.mem_offset),
              false));
      CopyMetadataTo(mem_ptr, addr);

    } else if (0ll > decl.mem_offset) {
      addr = ir.CreateSub(
        addr,
        llvm::ConstantInt::get(
            decl.mem_reg->type, static_cast<uint64_t>(-decl.mem_offset),
            false));
      CopyMetadataTo(mem_ptr, addr);
    }
    return llvm::dyn_cast<llvm::Instruction>(
        remill::LoadFromMemory(intrinsics, in_block, decl.type, mem_ptr, addr));

  // Store to memory at an absolute offset.
  } else if (decl.mem_offset) {
    llvm::IRBuilder<> ir(in_block);
    const auto addr = llvm::ConstantInt::get(
        remill::NthArgument(intrinsics.read_memory_8, 1u)->getType(),
        static_cast<uint64_t>(decl.mem_offset), false);
    return llvm::dyn_cast<llvm::Instruction>(
        remill::LoadFromMemory(intrinsics, in_block, decl.type, mem_ptr, addr));

  } else {
    return llvm::UndefValue::get(decl.type);
  }
}

}  // namespace anvill
