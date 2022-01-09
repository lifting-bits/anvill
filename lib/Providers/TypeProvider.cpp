/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Declarations.h>
#include <anvill/Providers.h>
#include <glog/logging.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/DenseMap.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Type.h>
#include <remill/Arch/Instruction.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Util.h>
#include <type_traits>

#include "Specification.h"

namespace anvill {

using ArchNameUT = std::underlying_type_t<remill::ArchName>;

class DefaultCallableTypeProviderImpl {
 public:
  const remill::ArchName default_arch;
  llvm::SmallDenseMap<ArchNameUT, CallableDecl, 16> decls;

  inline DefaultCallableTypeProviderImpl(remill::ArchName default_arch_)
      : default_arch(default_arch_) {}

  const CallableDecl *TryGetDeclForArch(remill::ArchName arch_) const {
    const auto arch = static_cast<ArchNameUT>(arch_);
    if (auto it = decls.find(arch); it != decls.end()) {
      return &(it->second);
    } else {
      return nullptr;
    }
  }
};

// Try to return the type of a function starting at address `address`. This
// type is the prototype of the function.
std::optional<FunctionDecl>
NullTypeProvider::TryGetFunctionType(uint64_t) const {
  return std::nullopt;
}

std::optional<VariableDecl>
NullTypeProvider::TryGetVariableType(uint64_t) const {
  return std::nullopt;
}

// Try to return the type of a function starting at address `to_address`. This
// type is the prototype of the function. The type can be call site specific,
// where the call site is `from_inst`.
std::optional<CallableDecl>
TypeProvider::TryGetCalledFunctionType(uint64_t function_address,
                                       const remill::Instruction &from_inst,
                                       uint64_t to_address) const {
  if (auto decl = TryGetCalledFunctionType(function_address, from_inst)) {
    return decl;
  } else if (auto func_decl = TryGetFunctionType(to_address)) {
    return static_cast<CallableDecl &>(func_decl.value());
  } else {
    return std::nullopt;
  }
}

// Try to return the type of a function that has been called from `from_isnt`.
std::optional<CallableDecl>
TypeProvider::TryGetCalledFunctionType(uint64_t function_address,
                                       const remill::Instruction &) const {
  return std::nullopt;
}

BaseTypeProvider::~BaseTypeProvider() {}

const ::anvill::TypeDictionary &BaseTypeProvider::Dictionary(void) const {
  return this->type_dictionary;
}

BaseTypeProvider::BaseTypeProvider(
    const ::anvill::TypeDictionary &type_dictionary_)
    : context(type_dictionary_.u.named.bool_->getContext()),
      type_dictionary(type_dictionary_) {}

// Try to get the type of the register named `reg_name` on entry to the
// instruction at `inst_address` inside the function beginning at
// `func_address`.
void BaseTypeProvider::QueryRegisterStateAtInstruction(
    uint64_t, uint64_t,
    std::function<void(const std::string &, llvm::Type *,
                       std::optional<uint64_t>)>) const {}

SpecificationTypeProvider::~SpecificationTypeProvider(void) {}

SpecificationTypeProvider::SpecificationTypeProvider(const Specification &spec)
    : BaseTypeProvider(spec.impl->type_translator),
      impl(spec.impl) {}

// Try to return the type of a function that has been called from `from_isnt`.
std::optional<CallableDecl> SpecificationTypeProvider::TryGetCalledFunctionType(
    uint64_t function_address, const remill::Instruction &from_inst) const {
  std::pair<std::uint64_t, std::uint64_t> loc{function_address, from_inst.pc};

  auto cs_it = impl->loc_to_call_site.find(loc);
  if (cs_it == impl->loc_to_call_site.end()) {
    return std::nullopt;
  } else {
    return *(cs_it->second);
  }
}

// Try to return the type of a function starting at address `address`. This
// type is the prototype of the function.
std::optional<anvill::FunctionDecl>
SpecificationTypeProvider::TryGetFunctionType(uint64_t address) const {
  auto func_it = impl->address_to_function.find(address);
  if (func_it == impl->address_to_function.end()) {
    return std::nullopt;
  } else {
    return *(func_it->second);
  }
}

std::optional<anvill::VariableDecl>
SpecificationTypeProvider::TryGetVariableType(uint64_t address) const {
  auto var_it = impl->address_to_var.find(address);
  if (var_it != impl->address_to_var.end()) {
    return *(var_it->second);
  } else {
    return std::nullopt;
  }
}

// Try to return the type of a function that has been called from `from_isnt`.
std::optional<CallableDecl>
DefaultCallableTypeProvider::TryGetCalledFunctionType(
    uint64_t function_address, const remill::Instruction &from_inst) const {
  auto maybe_res =
      ProxyTypeProvider::TryGetCalledFunctionType(function_address, from_inst);
  if (maybe_res.has_value()) {
    return maybe_res;
  }

  if (auto arch_decl = impl->TryGetDeclForArch(from_inst.arch_name)) {
    return *arch_decl;
  }

  if (from_inst.arch_name != from_inst.sub_arch_name) {
    if (auto sub_arch_decl = impl->TryGetDeclForArch(from_inst.sub_arch_name)) {
      return *sub_arch_decl;
    }
  }

  return std::nullopt;
}

std::optional<anvill::FunctionDecl>
DefaultCallableTypeProvider::TryGetFunctionType(uint64_t address) const {
  auto maybe_res = ProxyTypeProvider::TryGetFunctionType(address);
  if (maybe_res.has_value()) {
    return maybe_res;
  }

  auto arch_decl = impl->TryGetDeclForArch(impl->default_arch);
  if (!arch_decl) {
    return std::nullopt;
  }

  FunctionDecl fdecl;
  reinterpret_cast<CallableDecl &>(fdecl) = *arch_decl;
  fdecl.address = address;

  return fdecl;
}

DefaultCallableTypeProvider::~DefaultCallableTypeProvider(void) {}

// Initialize this type provider with a default architecture and a preferred
// type provider `deleg`.
DefaultCallableTypeProvider::DefaultCallableTypeProvider(
    remill::ArchName default_arch, const TypeProvider &deleg)
    : ProxyTypeProvider(deleg),
      impl(new DefaultCallableTypeProviderImpl(default_arch)){}

// Set `decl` to the default callable type for `arch`.
void DefaultCallableTypeProvider::SetDefault(
    remill::ArchName arch, CallableDecl decl) {
  impl->decls[arch] = std::move(decl);
}

// Try to return the type of a function starting at address `address`. This
// type is the prototype of the function.
std::optional<FunctionDecl>
ProxyTypeProvider::TryGetFunctionType(uint64_t address) const {
  return this->deleg.TryGetFunctionType(address);
}

// Try to return the type of a function that has been called from `from_isnt`.
std::optional<CallableDecl> ProxyTypeProvider::TryGetCalledFunctionType(
    uint64_t function_address, const remill::Instruction &from_inst) const {
  return this->deleg.TryGetCalledFunctionType(function_address, from_inst);
}

// Try to return the type of a function starting at address `to_address`. This
// type is the prototype of the function. The type can be call site specific,
// where the call site is `from_inst`.
std::optional<CallableDecl> ProxyTypeProvider::TryGetCalledFunctionType(
    uint64_t function_address, const remill::Instruction &from_inst,
    uint64_t to_address) const {
  return this->deleg.TryGetCalledFunctionType(function_address, from_inst,
                                              to_address);
}

// Try to return the variable at given address or containing the address
std::optional<VariableDecl>
ProxyTypeProvider::TryGetVariableType(uint64_t address) const {
  return this->deleg.TryGetVariableType(address);
}

// Try to get the type of the register named `reg_name` on entry to the
// instruction at `inst_address` inside the function beginning at
// `func_address`.
void ProxyTypeProvider::QueryRegisterStateAtInstruction(
    uint64_t func_address, uint64_t inst_address,
    std::function<void(const std::string &, llvm::Type *,
                       std::optional<uint64_t>)>
        typed_reg_cb) const {
  return this->deleg.QueryRegisterStateAtInstruction(func_address, inst_address,
                                                     typed_reg_cb);
}

const ::anvill::TypeDictionary &ProxyTypeProvider::Dictionary(void) const {
  return this->deleg.Dictionary();
}

ProxyTypeProvider::ProxyTypeProvider(const TypeProvider &deleg)
    : deleg(deleg) {}
}  // namespace anvill
