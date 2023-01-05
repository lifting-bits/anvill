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
#include <llvm/ADT/ArrayRef.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/Demangle/Demangle.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/Support/Casting.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/ABI.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Util.h>

#include <iterator>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "Arch/Arch.h"
#include "Protobuf.h"
#include "anvill/Specification.h"

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

void FunctionDecl::AddBBContexts(
    std::unordered_map<uint64_t, SpecBlockContext> &contexts) const {
  for (const auto &[addr, _] : this->cfg) {
    contexts.insert({addr, this->GetBlockContext(addr)});
  }
}


llvm::StructType *
BasicBlockContext::StructTypeFromVars(llvm::LLVMContext &llvm_context) const {
  std::vector<BasicBlockVariable> in_scope_locals =
      this->LiveParamsAtEntryAndExit();
  std::vector<llvm::Type *> field_types;
  std::transform(
      in_scope_locals.begin(), in_scope_locals.end(),
      std::back_inserter(field_types),
      [](const BasicBlockVariable &param) { return param.param.type; });

  return llvm::StructType::get(llvm_context, field_types,
                               "sty_for_basic_block_function");
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

const std::vector<ValueDecl> &SpecBlockContext::ReturnValue() const {
  return this->decl.returns;
}


SpecBlockContext::SpecBlockContext(
    const FunctionDecl &decl, SpecStackOffsets offsets,
    std::vector<ParameterDecl> live_params_at_entry,
    std::vector<ParameterDecl> live_params_at_exit)
    : decl(decl),
      offsets(std::move(offsets)),
      live_params_at_entry(std::move(live_params_at_entry)),
      live_params_at_exit(std::move(live_params_at_exit)) {}

const std::vector<ParameterDecl> &SpecBlockContext::LiveParamsAtExit() const {
  return this->live_params_at_exit;
}

const std::vector<ParameterDecl> &SpecBlockContext::LiveParamsAtEntry() const {
  return this->live_params_at_entry;
}

const SpecStackOffsets &SpecBlockContext::GetStackOffsets() const {
  return this->offsets;
}

// Interpret `target` as being the function to call, and call it from within
// a basic block in a lifted bitcode function. Returns the new value of the
// memory pointer.
llvm::Value *CallableDecl::CallFromLiftedBlock(
    llvm::Value *target, const anvill::TypeDictionary &types,
    const remill::IntrinsicTable &intrinsics, llvm::IRBuilder<> &ir,
    llvm::Value *state_ptr, llvm::Value *mem_ptr) const {
  auto module = ir.GetInsertBlock()->getModule();
  auto &context = module->getContext();
  CHECK_EQ(&context, &(target->getContext()));
  CHECK_EQ(&context, &(state_ptr->getContext()));
  CHECK_EQ(&context, &(mem_ptr->getContext()));
  CHECK_EQ(&context, &(types.u.named.void_->getContext()));

  // Go and get a pointer to the stack pointer register, so that we can
  // later store our computed return value stack pointer to it.
  auto sp_reg = arch->RegisterByName(arch->StackPointerRegisterName());
  const auto ptr_to_sp = sp_reg->AddressOf(state_ptr, ir);


  // Go and compute the value of the stack pointer on exit from
  // the function, which will be based off of the register state
  // on entry to the function.
  auto new_sp_base = return_stack_pointer->AddressOf(state_ptr, ir);

  const auto sp_val_on_exit = ir.CreateAdd(
      ir.CreateLoad(return_stack_pointer->type, new_sp_base),
      llvm::ConstantInt::get(return_stack_pointer->type,
                             static_cast<uint64_t>(return_stack_pointer_offset),
                             true));

  llvm::SmallVector<llvm::Value *, 4> param_vals;

  // Get the return address.
  auto ret_addr = LoadLiftedValue(return_address, types, intrinsics, ir,
                                  state_ptr, mem_ptr);
  CHECK(ret_addr && !llvm::isa_and_nonnull<llvm::UndefValue>(ret_addr));

  // Get the parameters.
  for (const auto &param_decl : params) {
    const auto val =
        LoadLiftedValue(param_decl, types, intrinsics, ir, state_ptr, mem_ptr);
    if (auto inst_val = llvm::dyn_cast<llvm::Instruction>(val)) {
      inst_val->setName(param_decl.name);
    }
    param_vals.push_back(val);
  }

  llvm::CallInst *ret_val = nullptr;
  if (auto func = llvm::dyn_cast<llvm::Function>(target)) {
    ret_val = ir.CreateCall(func, param_vals);
  } else {
    auto func_type = llvm::dyn_cast<llvm::FunctionType>(
        remill::RecontextualizeType(type, context));
    ret_val = ir.CreateCall(func_type, target, param_vals);
  }

  if (is_noreturn) {
    ret_val->setDoesNotReturn();
  }

  // There is a single return value, store it to the lifted state.
  if (returns.size() == 1) {
    auto call_ret = ret_val;

    mem_ptr = StoreNativeValue(call_ret, returns.front(), types, intrinsics, ir,
                               state_ptr, mem_ptr);

    // There are possibly multiple return values (or zero). Unpack the
    // return value (it will be a struct type) into its components and
    // write each one out into the lifted state.
  } else {
    unsigned index = 0;
    for (const auto &ret_decl : returns) {
      unsigned indexes[] = {index};
      auto elem_val = ir.CreateExtractValue(ret_val, indexes);
      mem_ptr = StoreNativeValue(elem_val, ret_decl, types, intrinsics, ir,
                                 state_ptr, mem_ptr);
      index += 1;
    }
  }

  // TODO(Ian): ... well ok so we already did stuff assuming the PC was one way since we lifted below it.
  //ir.CreateStore(ret_addr, remill::FindVarInFunction(
  //                           ir.GetInsertBlock(), remill::kNextPCVariableName)
  //                         .first);
  ir.CreateStore(sp_val_on_exit, ptr_to_sp);

  if (is_noreturn) {
    return llvm::UndefValue::get(mem_ptr->getType());
  } else {
    return mem_ptr;
  }
}

anvill::Result<CallableDecl, std::string>
CallableDecl::DecodeFromPB(const remill::Arch *arch, const std::string &pb) {
  ::specification::Function function;
  if (!function.ParseFromString(pb)) {
    return {"Failed to parse callable decl"};
  }

  const TypeDictionary type_dictionary(*(arch->context));
  const TypeTranslator type_translator(type_dictionary, arch);
  std::unordered_map<std::int64_t, TypeSpec> type_map;
  ProtobufTranslator translator(type_translator, arch, type_map);

  auto default_callable_decl_res =
      translator.DecodeDefaultCallableDecl(function);
  if (!default_callable_decl_res.Succeeded()) {
    return {"Failed to decode to default callable decl"};
  }

  return default_callable_decl_res.Value();
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

namespace {
template <class V>
V GetWithDef(uint64_t addr, const std::unordered_map<uint64_t, V> &map, V def) {
  if (map.find(addr) == map.end()) {
    return def;
  }

  return map.find(addr)->second;
}
}  // namespace

SpecBlockContext FunctionDecl::GetBlockContext(std::uint64_t addr) const {
  return SpecBlockContext(
      *this, GetWithDef(addr, this->stack_offsets, SpecStackOffsets()),
      GetWithDef(addr, this->live_regs_at_entry, std::vector<ParameterDecl>()),
      GetWithDef(addr, this->live_regs_at_exit, std::vector<ParameterDecl>()));
}


}  // namespace anvill
