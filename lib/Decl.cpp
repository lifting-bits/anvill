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

#include <gflags/gflags.h>
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
#include <llvm/Support/JSON.h>
#include <llvm/Demangle/Demangle.h>

#include <remill/Arch/Arch.h>
#include <remill/BC/ABI.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Util.h>

#include "Lift.h"
#include "anvill/Arch.h"
#include "anvill/TypePrinter.h"

DEFINE_bool(demangle_names, false, "Demangle function and variable names");

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

// Serialize a FunctionDecl to JSON
llvm::json::Object FunctionDecl::SerializeToJSON() {
  llvm::json::Object json;

  std::string output_name;
  if (FLAGS_demangle_names) {
    output_name = this->demangled_name;
  } else {
    output_name = this->name;
  }
  json.insert(
      llvm::json::Object::KV{llvm::json::ObjectKey("name"), output_name});

  llvm::json::Array params_json;
  for (auto pdecl : this->params) {
    llvm::json::Value v = llvm::json::Value(pdecl.SerializeToJSON(*this->dl));
    params_json.push_back(v);
  }
  json.insert(
      llvm::json::Object::KV{llvm::json::ObjectKey("parameters"),
                             llvm::json::Value(std::move(params_json))});

  llvm::json::Array returns_json;
  for (auto rdecl : this->returns) {
    returns_json.push_back(llvm::json::Value(rdecl.SerializeToJSON(*this->dl)));
  }
  json.insert(
      llvm::json::Object::KV{llvm::json::ObjectKey("return values"),
                             llvm::json::Value(std::move(returns_json))});

  if (this->return_stack_pointer) {
    llvm::json::Object return_stack_pointer_json;
    return_stack_pointer_json.insert(llvm::json::Object::KV{
        llvm::json::ObjectKey("register"), this->return_stack_pointer->name});
    return_stack_pointer_json.insert(llvm::json::Object::KV{
        llvm::json::ObjectKey("offset"), this->return_stack_pointer_offset});
    return_stack_pointer_json.insert(llvm::json::Object::KV{
        llvm::json::ObjectKey("type"),
        TranslateType(*this->return_stack_pointer->type, *this->dl)});

    json.insert(llvm::json::Object::KV{
        llvm::json::ObjectKey("return stack pointer"),
        llvm::json::Value(std::move(return_stack_pointer_json))});
  }
  return json;
}

// Serialize a ParameterDecl to JSON
llvm::json::Object ParameterDecl::SerializeToJSON(const llvm::DataLayout &dl) {
  // Get the serialization for the ValueDecl
  ValueDecl *val_decl_ptr = dynamic_cast<ValueDecl *>(this);
  llvm::json::Object param_json = val_decl_ptr->SerializeToJSON(dl);

  // Insert "name"
  param_json.insert(
      llvm::json::Object::KV{llvm::json::ObjectKey("name"), this->name});

  return param_json;
}

// Serialize a ValueDecl to JSON
llvm::json::Object ValueDecl::SerializeToJSON(const llvm::DataLayout &dl) {
  llvm::json::Object value_json;

  if (this->reg) {
    // The value is in a register
    value_json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("register"),
                                             this->reg->name});
  } else if (this->mem_reg) {
    // The value is in memory
    llvm::json::Object memory_json;
    memory_json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("register"),
                                              this->mem_reg->name});
    memory_json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("offset"),
                                              this->mem_offset});

    // Wrap the memory_json structure in a memory block
    value_json.insert(
        llvm::json::Object::KV{llvm::json::ObjectKey("memory"),
                               llvm::json::Value(std::move(memory_json))});
  } else {
    LOG(ERROR) << "Trying to serialize a value that has not been allocated";
    exit(1);
  }

  value_json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("type"),
                                           TranslateType(*this->type, dl)});

  return value_json;
}

// Create a Function Declaration from llvm::Function
FunctionDecl FunctionDecl::Create(const llvm::Function &func, const llvm::Module &mdl) {
  const llvm::DataLayout dl = mdl.getDataLayout();
  const remill::Arch* arch = remill::Arch::GetModuleArch(mdl);

  FunctionDecl decl;
  decl.type = func.getFunctionType();
  
  decl.name = func.getName().data();
  decl.demangled_name = llvm::demangle(func.getName().data());
  decl.dl = &dl;

  // Try to guess the parameter and return value register allocation by looking
  // at the calling convention of the function
  llvm::CallingConv::ID cc_id = func.getCallingConv();
  std::unique_ptr<CallingConvention> cc = nullptr;

  switch (cc_id) {
    case llvm::CallingConv::X86_64_SysV:
      cc = std::unique_ptr<anvill::X86_64_SysV>(new X86_64_SysV(arch));
      break;
    default:
      // TODO(aty): find a better way to do this since the calling conventions given
      // by llvm::function cannot be trusted
      cc = std::unique_ptr<anvill::X86_C>(new X86_C(arch));
  }

  cc->AllocateSignature(decl, func);

  // TODO(aty): for a better and more comprehensive serialization
  // decl->address =
  // decl->return_address =
  // decl->return_stack_pointer =
  // decl->return_stack_pointer_offset =
  // decl->is_noreturn =
  // decl->is_variadic =
  // decl->num_bytes_in_redzone =

  return decl;
}

}  // namespace anvill
