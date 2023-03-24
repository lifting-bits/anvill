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

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "Arch/Arch.h"
#include "Protobuf.h"
#include "anvill/Specification.h"


namespace {

template <class T>
inline void hash_combine(std::size_t &seed, const T &v) {
  std::hash<T> hasher;
  seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

}  // namespace


namespace std {
template <>
struct std::hash<anvill::LowLoc> {
  std::size_t operator()(const anvill::LowLoc &c) const {
    std::size_t result = 0;

    hash_combine(result, c.mem_reg);
    hash_combine(result, c.mem_offset);
    hash_combine(result, c.reg);
    hash_combine(result, c.size);
    return result;
  }
};
}  // namespace std

namespace anvill {

bool LowLoc::operator==(const LowLoc &loc) const {
  return reg == loc.reg && mem_reg == loc.mem_reg &&
         loc.mem_offset == mem_offset && loc.size == size;
}

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

std::uint64_t LowLoc::Size() const {
  if (this->size) {
    return *this->size;
  } else {
    return this->reg->size;
  }
}


// need to be careful here about overlapping values
std::vector<BasicBlockVariable>
BasicBlockContext::LiveParamsAtEntryAndExit() const {
  auto live_exits = this->LiveParamsAtExit();
  auto live_entries = this->LiveParamsAtEntry();


  auto add_to_set = [](const std::vector<ParameterDecl> &params,
                       std::unordered_set<LowLoc> &locs_to_add) {
    for (const auto &p : params) {
      std::copy(p.oredered_locs.begin(), p.oredered_locs.end(),
                std::inserter(locs_to_add, locs_to_add.end()));
    }
  };

  std::unordered_set<LowLoc> covered_live_ent;
  add_to_set(live_entries, covered_live_ent);
  std::unordered_set<LowLoc> covered_live_exit;
  add_to_set(live_exits, covered_live_exit);

  std::vector<BasicBlockVariable> res;
  std::unordered_set<LowLoc> covered;
  auto add_all_from_vector =
      [&res, &covered, &covered_live_ent,
       &covered_live_exit](std::vector<ParameterDecl> params) {
        for (auto p : params) {
          auto completely_covered =
              std::all_of(p.oredered_locs.begin(), p.oredered_locs.end(),
                          [&covered](const LowLoc &loc) -> bool {
                            return covered.find(loc) != covered.end();
                          });
          auto live_at_ent = std::any_of(
              p.oredered_locs.begin(), p.oredered_locs.end(),
              [&covered_live_ent](const LowLoc &loc) -> bool {
                return covered_live_ent.find(loc) != covered_live_ent.end();
              });
          auto live_at_exit = std::any_of(
              p.oredered_locs.begin(), p.oredered_locs.end(),
              [&covered_live_exit](const LowLoc &loc) -> bool {
                return covered_live_exit.find(loc) != covered_live_exit.end();
              });

          if (!completely_covered) {
            std::copy(p.oredered_locs.begin(), p.oredered_locs.end(),
                      std::inserter(covered, covered.end()));
            res.push_back({p, live_at_ent, live_at_exit});
          }
        }
      };

  add_all_from_vector(live_entries);
  add_all_from_vector(live_exits);
  return res;
}


std::vector<BasicBlockVariable> BasicBlockContext::LiveBBParamsAtEntry() const {
  auto alllive = this->LiveParamsAtEntryAndExit();
  std::vector<BasicBlockVariable> res;
  std::copy_if(
      alllive.begin(), alllive.end(), std::back_inserter(res),
      [](const BasicBlockVariable &bbvar) { return bbvar.live_at_entry; });
  return res;
}

std::vector<BasicBlockVariable> BasicBlockContext::LiveBBParamsAtExit() const {
  auto alllive = this->LiveParamsAtEntryAndExit();
  std::vector<BasicBlockVariable> res;
  std::copy_if(
      alllive.begin(), alllive.end(), std::back_inserter(res),
      [](const BasicBlockVariable &bbvar) { return bbvar.live_at_exit; });
  return res;
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

size_t BasicBlockContext::GetParamIndex(const ParameterDecl &decl) const {
  auto stack_var = std::find_if(
      GetParams().begin(), GetParams().end(), [&](const ParameterDecl &param) {
        if (param.oredered_locs.size() != decl.oredered_locs.size()) {
          return false;
        }

        for (size_t i{0}; i < param.oredered_locs.size(); ++i) {
          if (param.oredered_locs[i].reg &&
              param.oredered_locs[i].reg != decl.oredered_locs[i].reg) {
            return false;
          }

          if (param.oredered_locs[i].mem_reg != decl.oredered_locs[i].mem_reg) {
            return false;
          }

          if (param.oredered_locs[i].mem_offset !=
              decl.oredered_locs[i].mem_offset) {
            return false;
          }
        }
        return true;
      });
  CHECK(stack_var != GetParams().end());
  return stack_var - GetParams().begin();
}

llvm::Value *BasicBlockContext::ProvidePointerFromStruct(
    llvm::IRBuilder<> &ir, llvm::StructType *sty, llvm::Value *target_sty,
    const ParameterDecl &decl) const {
  auto i32 = llvm::IntegerType::get(ir.getContext(), 32);
  auto index = GetParamIndex(decl);
  auto ptr = ir.CreateGEP(
      sty, target_sty,
      {llvm::ConstantInt::get(i32, 0), llvm::ConstantInt::get(i32, index)});
  return ptr;
}

llvm::Argument *BasicBlockContext::ProvidePointerFromFunctionArgs(
    llvm::Function *func, const ParameterDecl &param) const {
  return func->getArg(GetParamIndex(param) + remill::kNumBlockArgs + 1);
}

ValueDecl SpecBlockContext::ReturnValue() const {
  return this->decl.returns;
}

uint64_t SpecBlockContext::GetParentFunctionAddress() const {
  return this->decl.address;
}

size_t SpecBlockContext::GetStackSize() const {
  return decl.stack_depth;
}

size_t SpecBlockContext::GetMaxStackSize() const {
  return decl.maximum_depth;
}


SpecBlockContext::SpecBlockContext(
    const FunctionDecl &decl, SpecStackOffsets offsets,
    std::vector<ConstantDomain> constants,
    std::vector<ParameterDecl> live_params_at_entry,
    std::vector<ParameterDecl> live_params_at_exit)
    : decl(decl),
      offsets(std::move(offsets)),
      constants(std::move(constants)),
      live_params_at_entry(std::move(live_params_at_entry)),
      live_params_at_exit(std::move(live_params_at_exit)),
      params(decl.in_scope_variables) {}

size_t SpecBlockContext::GetPointerDisplacement() const {
  return this->decl.GetPointerDisplacement();
}

const std::vector<ParameterDecl> &SpecBlockContext::LiveParamsAtExit() const {
  return this->live_params_at_exit;
}

const std::vector<ParameterDecl> &SpecBlockContext::LiveParamsAtEntry() const {
  return this->live_params_at_entry;
}

const SpecStackOffsets &SpecBlockContext::GetStackOffsets() const {
  return this->offsets;
}

const std::vector<ConstantDomain> &SpecBlockContext::GetConstants() const {
  return this->constants;
}

const std::vector<ParameterDecl> &SpecBlockContext::GetParams() const {
  return this->params;
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
  LOG(INFO) << "Modifying ret stack pointer by: "
            << return_stack_pointer_offset;

  // TODO(Ian): this could go in the wrong direction if stack option is set to go up
  const auto sp_val_on_exit = ir.CreateAdd(
      ir.CreateLoad(return_stack_pointer->type, new_sp_base),
      llvm::ConstantInt::get(return_stack_pointer->type,
                             static_cast<uint64_t>(return_stack_pointer_offset),
                             true));

  llvm::SmallVector<llvm::Value *, 4> param_vals;

  // Get the return address.
  auto ret_addr = LoadLiftedValue(return_address, types, intrinsics, this->arch,
                                  ir, state_ptr, mem_ptr);
  CHECK(ret_addr && !llvm::isa_and_nonnull<llvm::UndefValue>(ret_addr));

  // Get the parameters.
  for (const auto &param_decl : params) {
    const auto val = LoadLiftedValue(param_decl, types, intrinsics, this->arch,
                                     ir, state_ptr, mem_ptr);
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

  auto call_ret = ret_val;
  if (!call_ret->getType()->isVoidTy()) {
    mem_ptr = StoreNativeValue(call_ret, this->returns, types, intrinsics, ir,
                               state_ptr, mem_ptr);
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
  auto new_func_type = llvm::FunctionType::get(
      this->returns.type, this->type->params(), this->type->isVarArg());
  this->type = new_func_type;
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

size_t FunctionDecl::GetPointerDisplacement() const {
  return this->parameter_size + this->parameter_offset;
}

SpecBlockContext FunctionDecl::GetBlockContext(std::uint64_t addr) const {
  return SpecBlockContext(
      *this, GetWithDef(addr, this->stack_offsets, SpecStackOffsets()),
      GetWithDef(addr, this->constant_values, std::vector<ConstantDomain>()),
      GetWithDef(addr, this->live_regs_at_entry, std::vector<ParameterDecl>()),
      GetWithDef(addr, this->live_regs_at_exit, std::vector<ParameterDecl>()));
}

std::optional<size_t>
AbstractStack::StackOffsetFromStackPointer(std::int64_t stack_off) const {
  if (this->stack_grows_down) {
    auto displaced_offset =
        stack_off - static_cast<std::int64_t>(this->pointer_displacement);
    LOG(INFO) << this->total_size;
    LOG(INFO) << "disp: " << this->pointer_displacement;
    LOG(INFO) << "Displaced offset: " << displaced_offset;
    if (!(static_cast<std::int64_t>(this->total_size) >=
          llabs(displaced_offset))) {
      return std::nullopt;
    }
    return this->total_size + displaced_offset;
  } else {
    return this->pointer_displacement + stack_off;
  }
}

std::int64_t AbstractStack::StackPointerFromStackOffset(size_t offset) const {
  if (stack_grows_down) {
    return (static_cast<std::int64_t>(offset) - this->total_size) +
           this->pointer_displacement;
  } else {
    return offset - this->pointer_displacement;
  }
}


std::optional<std::int64_t>
AbstractStack::StackPointerFromStackCompreference(llvm::Value *tgt) const {
  size_t curr_off = 0;
  for (auto comp : this->components) {
    if (comp.stackptr == tgt) {
      return this->StackPointerFromStackOffset(curr_off);
    }
    curr_off += comp.size;
  }

  return std::nullopt;
}

std::optional<llvm::Value *>
AbstractStack::PointerToStackMemberFromOffset(llvm::IRBuilder<> &ir,
                                              std::int64_t stack_off) const {
  auto off = this->StackOffsetFromStackPointer(stack_off);
  if (!off) {
    return std::nullopt;
  }

  auto i32 = llvm::IntegerType::getInt32Ty(this->context);
  LOG(INFO) << "Looking for offset" << *off;
  auto curr_off = 0;
  auto curr_ind = 0;
  for (auto [sz, ptr] : this->components) {
    if (off < curr_off + sz) {
      LOG(INFO) << "Found for " << remill::LLVMThingToString(ptr);
      LOG(INFO) << curr_off << " " << sz;
      return ir.CreateGEP(this->stack_types[curr_ind], ptr,
                          {llvm::ConstantInt::get(i32, 0),
                           llvm::ConstantInt::get(i32, *off - curr_off)});
    }
    curr_off += sz;
    curr_ind++;
  }

  return std::nullopt;
}

llvm::Type *AbstractStack::StackTypeFromSize(llvm::LLVMContext &context,
                                             size_t size) {
  return llvm::ArrayType::get(llvm::IntegerType::getInt8Ty(context), size);
}


AbstractStack::AbstractStack(llvm::LLVMContext &context,
                             std::vector<StackComponent> components,
                             bool stack_grows_down, size_t pointer_displacement)
    : context(context),
      stack_grows_down(stack_grows_down),
      components(std::move(components)),
      total_size(0),
      pointer_displacement(pointer_displacement) {

  if (stack_grows_down) {
    std::reverse(this->components.begin(), this->components.end());
  }

  for (const auto &[k, v] : this->components) {
    this->stack_types.push_back(this->StackTypeFromSize(context, k));
    total_size += k;
  }
}

}  // namespace anvill
