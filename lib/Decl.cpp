/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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

#include "anvill/Decl.h"

#include <glog/logging.h>

#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include <remill/Arch/Arch.h>
#include <remill/BC/ABI.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Util.h>

#include "Lift.h"

namespace anvill {

// Declare this global variable in an LLVM module.
llvm::GlobalVariable *GlobalVarDecl::DeclareInModule(
    llvm::Module &target_module) const {
  if (!is_valid) {
    return nullptr;
  }

  auto &context = target_module.getContext();
  auto var_type = remill::RecontextualizeType(type, context);

  auto existing_var = target_module.getGlobalVariable(name);
  if (existing_var && existing_var->getValueType() == var_type) {
    return existing_var;
  }

  return new llvm::GlobalVariable(
      target_module, var_type, false,
      llvm::GlobalValue::ExternalLinkage,
      nullptr, name);
}

// Declare this function in an LLVM module.
llvm::Function *FunctionDecl::DeclareInModule(
    llvm::Module &target_module) const {
  if (!is_valid) {
    return nullptr;
  }

  auto &context = target_module.getContext();
  auto func_type = llvm::dyn_cast<llvm::FunctionType>(
      remill::RecontextualizeType(type, context));

  auto existing_func = target_module.getFunction(name);
  if (existing_func && existing_func->getFunctionType() == func_type) {
    return existing_func;
  }

  llvm::Function *func = llvm::Function::Create(
      func_type, llvm::GlobalValue::ExternalLinkage,
      name, &target_module);
  func->addFnAttr(llvm::Attribute::NoInline);

  if (is_noreturn) {
    func->addFnAttr(llvm::Attribute::NoReturn);
  }

  // Give them all nice names :-D
  auto arg_num = 0U;
  for (auto &arg : func->args()) {
    arg.setName(params[arg_num++].name);
  }

  return func;
}

// Create a call to this function from within a basic block in a
// lifted bitcode function. Returns the new value of the memory
// pointer.
llvm::Value *FunctionDecl::CallFromLiftedBlock(
    const remill::IntrinsicTable &intrinsics,
    llvm::BasicBlock *block,
    llvm::Value *state_ptr,
    llvm::Value *mem_ptr) const {

  if (!is_valid) {
    return llvm::UndefValue::get(mem_ptr->getType());
  }

  auto module = block->getModule();
  auto func = DeclareInModule(*module);
  llvm::IRBuilder<> ir(block);

  // Initialize the program counter on entry to this function.
  auto pc_reg = arch->RegisterByName(arch->ProgramCounterRegisterName());
  auto ptr_to_pc = pc_reg->AddressOf(state_ptr, block);
  ir.SetInsertPoint(block);
  ir.CreateStore(
      llvm::ConstantInt::get(pc_reg->type, address, false),
      ptr_to_pc);

  // Go and get a pointer to the stack pointer register, so that we can
  // later store our computed return value stack pointer to it.
  auto sp_reg = arch->RegisterByName(arch->StackPointerRegisterName());
  const auto ptr_to_sp = sp_reg->AddressOf(state_ptr, block);
  ir.SetInsertPoint(block);

  // Go and compute the value of the stack pointer on exit from
  // the function, which will be based off of the register state
  // on entry to the function.
  auto new_sp_base = return_stack_pointer->AddressOf(state_ptr, block);
  ir.SetInsertPoint(block);

  const auto sp_val_on_exit = ir.CreateAdd(
      ir.CreateLoad(new_sp_base),
      llvm::ConstantInt::get(return_stack_pointer->type,
                             static_cast<uint64_t>(return_stack_pointer_offset),
                             true));

  llvm::SmallVector<llvm::Value *, 4> param_vals;

  // Get the return address.
  auto ret_addr = LoadLiftedValue(
      return_address, intrinsics, block, state_ptr, mem_ptr);

  // Get the parameters.
  for (const auto &param_decl : params) {
    const auto val = LoadLiftedValue(
        param_decl, intrinsics, block, state_ptr, mem_ptr);
    if (auto inst_val = llvm::dyn_cast<llvm::Instruction>(val)) {
      inst_val->setName(param_decl.name);
    }
    param_vals.push_back(val);
  }

  auto ret_val = ir.CreateCall(func, param_vals);
  (void) ret_val;

  // There is a single return value, store it to the lifted state.
  if (returns.size() == 1) {
    mem_ptr = StoreNativeValue(
        ret_val, returns.front(), intrinsics, block,
        state_ptr, mem_ptr);

  // There are possibly multiple return values (or zero). Unpack the
  // return value (it will be a struct type) into its components and
  // write each one out into the lifted state.
  } else {
    unsigned index = 0;
    for (const auto &ret_decl : returns) {
      unsigned indexes[] = {index};
      auto elem_val = ir.CreateExtractValue(ret_val, indexes);
      mem_ptr = StoreNativeValue(
          elem_val, ret_decl, intrinsics, block,
          state_ptr, mem_ptr);
      index += 1;
    }
  }

  // Store the return address, and computed return stack pointer.
  ir.SetInsertPoint(block);
  ir.CreateStore(ret_addr, ptr_to_pc);
  ir.CreateStore(sp_val_on_exit, ptr_to_sp);

  if (is_noreturn) {
    return llvm::UndefValue::get(mem_ptr->getType());
  } else {
    return mem_ptr;
  }
}

}  // namespace anvill
