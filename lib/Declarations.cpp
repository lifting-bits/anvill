/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Declarations.h>
#include <anvill/Type.h>
#include <anvill/Utils.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/Demangle/Demangle.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/ABI.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Util.h>

#include "Arch/Arch.h"

namespace anvill {

// Declare this global variable in an LLVM module.
llvm::GlobalVariable *
VariableDecl::DeclareInModule(const std::string &name,
                              llvm::Module &target_module) const {
  auto &context = target_module.getContext();
  auto var_type = remill::RecontextualizeType(type, context);

  auto existing_var = target_module.getGlobalVariable(name);
  if (existing_var && existing_var->getValueType() == var_type) {
    return existing_var;
  }

  return new llvm::GlobalVariable(target_module, var_type, false,
                                  llvm::GlobalValue::ExternalLinkage, nullptr,
                                  name);
}

// Declare this function in an LLVM module.
llvm::Function *
FunctionDecl::DeclareInModule(std::string_view name,
                              llvm::Module &target_module) const {
  auto &context = target_module.getContext();
  auto func_type = llvm::dyn_cast<llvm::FunctionType>(
      remill::RecontextualizeType(type, context));

  auto existing_func = target_module.getFunction(name);
  if (existing_func && existing_func->getFunctionType() == func_type) {
    return existing_func;
  }

  DLOG_IF(ERROR, existing_func)
      << "Re-defining " << name << "; previous version has type "
      << remill::LLVMThingToString(existing_func->getFunctionType())
      << " whereas new version has type "
      << remill::LLVMThingToString(func_type);

  llvm::StringRef name_(name.data(), name.size());
  llvm::Function *func = llvm::Function::Create(
      func_type, llvm::GlobalValue::ExternalLinkage, name_, &target_module);
  DCHECK_EQ(func->getName().str(), name);

  func->addFnAttr(llvm::Attribute::NoInline);

  if (is_noreturn) {
    func->addFnAttr(llvm::Attribute::NoReturn);
  }

  func->setCallingConv(calling_convention);

  // Give them all nice names :-D
  auto arg_num = 0u;
  for (auto &arg : func->args()) {
    arg.setName(params[arg_num++].name);
  }

  return func;
}

// Interpret `target` as being the function to call, and call it from within
// a basic block in a lifted bitcode function. Returns the new value of the
// memory pointer.
llvm::Value *CallableDecl::CallFromLiftedBlock(
    llvm::Value *target, const anvill::TypeDictionary &types,
    const remill::IntrinsicTable &intrinsics, llvm::BasicBlock *block,
    llvm::Value *state_ptr, llvm::Value *mem_ptr) const {
  auto module = block->getModule();
  auto &context = module->getContext();
  CHECK_EQ(&context, &(target->getContext()));
  CHECK_EQ(&context, &(state_ptr->getContext()));
  CHECK_EQ(&context, &(mem_ptr->getContext()));
  CHECK_EQ(&context, &(types.u.named.void_->getContext()));

  llvm::IRBuilder<> ir(block);

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
      ir.CreateLoad(return_stack_pointer->type, new_sp_base),
      llvm::ConstantInt::get(return_stack_pointer->type,
                             static_cast<uint64_t>(return_stack_pointer_offset),
                             true));

  llvm::SmallVector<llvm::Value *, 4> param_vals;

  // Get the return address.
  auto ret_addr = LoadLiftedValue(return_address, types, intrinsics, block,
                                  state_ptr, mem_ptr);

  // Get the parameters.
  for (const auto &param_decl : params) {
    const auto val = LoadLiftedValue(param_decl, types, intrinsics, block,
                                     state_ptr, mem_ptr);
    if (auto inst_val = llvm::dyn_cast<llvm::Instruction>(val)) {
      inst_val->setName(param_decl.name);
    }
    param_vals.push_back(val);
  }

  llvm::Value *ret_val = nullptr;
  if (auto func = llvm::dyn_cast<llvm::Function>(target)) {
    ret_val = ir.CreateCall(func, param_vals);
  } else {
    auto func_type = llvm::dyn_cast<llvm::FunctionType>(
        remill::RecontextualizeType(type, context));
    ret_val = ir.CreateCall(func_type, target, param_vals);
  }
  (void) ret_val;

  // There is a single return value, store it to the lifted state.
  if (returns.size() == 1) {
    auto call_ret = ret_val;

    mem_ptr = StoreNativeValue(call_ret, returns.front(), types, intrinsics,
                               block, state_ptr, mem_ptr);

    // There are possibly multiple return values (or zero). Unpack the
    // return value (it will be a struct type) into its components and
    // write each one out into the lifted state.
  } else {
    unsigned index = 0;
    for (const auto &ret_decl : returns) {
      unsigned indexes[] = {index};
      auto elem_val = ir.CreateExtractValue(ret_val, indexes);
      mem_ptr = StoreNativeValue(elem_val, ret_decl, types, intrinsics, block,
                                 state_ptr, mem_ptr);
      index += 1;
    }
  }

  // Store the return address, and computed return stack pointer.
  ir.SetInsertPoint(block);

  ir.CreateStore(ret_addr, remill::FindVarInFunction(block, "NEXT_PC"));
  ir.CreateStore(sp_val_on_exit, ptr_to_sp);

  if (is_noreturn) {
    return llvm::UndefValue::get(mem_ptr->getType());
  } else {
    return mem_ptr;
  }
}

// Create a Function Declaration from an `llvm::Function`.
Result<FunctionDecl, std::string>
FunctionDecl::Create(llvm::Function &func, const remill::Arch *arch) {

  // If the function calling convention is not the default llvm::CallingConv::C
  // then use it. Otherwise, get the CallingConvention from the remill::Arch
  std::unique_ptr<CallingConvention> cc;
  llvm::CallingConv::ID cc_id = func.getCallingConv();

  Result<CallingConvention::Ptr, std::string> maybe_cc;

  // The value is not default so use it.
  if (cc_id != llvm::CallingConv::C) {
    maybe_cc = CallingConvention::CreateCCFromArchAndID(arch, cc_id);

    // Figure out the default calling convention for this triple.
  } else {
    maybe_cc = CallingConvention::CreateCCFromArch(arch);
  }

  if (maybe_cc.Succeeded()) {
    maybe_cc.TakeValue().swap(cc);
  } else {
    std::stringstream ss;
    ss << "Calling convention of function '" << func.getName().str()
       << "' is not supported: " << maybe_cc.TakeError();
    return ss.str();
  }

  return cc->AllocateSignature(func);
}


void CallableDecl::OverrideFunctionTypeWithABIParamLayout() {
  llvm::SmallVector<llvm::Type *> new_args;
  for (const auto &par : this->params) {
    new_args.push_back(par.type);
  }

  this->type = llvm::FunctionType::get(this->type->getReturnType(), new_args,
                                       this->type->isVarArg());

  return;
}

void CallableDecl::OverrideFunctionTypeWithABIReturnLayout() {
  if (this->returns.size() < 1) {
    return;
  } else if (this->returns.size() == 1) {
    // Override the return type with the type of the last return
    auto new_func_type =
        llvm::FunctionType::get(this->returns.front().type,
                                this->type->params(), this->type->isVarArg());
    this->type = new_func_type;
  } else {
    // Create a structure that has a field for each return
    std::vector<llvm::Type *> elems;
    for (const auto &ret : this->returns) {
      elems.push_back(ret.type);
    }

    auto ret_type_struct = llvm::StructType::create(elems);

    auto new_func_type = llvm::FunctionType::get(
        ret_type_struct, this->type->params(), this->type->isVarArg());
    this->type = new_func_type;
  }
}

}  // namespace anvill
