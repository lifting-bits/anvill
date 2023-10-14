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
#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Type.h>
#include <remill/Arch/Instruction.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Util.h>

#include <algorithm>
#include <optional>
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
NullTypeProvider::TryGetVariableType(uint64_t, llvm::Type *) const {
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

SpecificationTypeProvider::SpecificationTypeProvider(const Specification &spec,
                                                     llvm::DataLayout layout)
    : BaseTypeProvider(spec.impl->type_translator),
      impl(spec.impl),
      layout(layout) {}

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
SpecificationTypeProvider::TryGetVariableType(uint64_t address,
                                              llvm::Type *) const {

  auto var_it = impl->address_to_var.lower_bound(address);
  if (var_it != impl->address_to_var.begin() && var_it->first != address) {
    var_it--;
  }

  auto v = var_it->second;
  CHECK(v->type);
  if (v->type && address >= v->address &&
      address < v->address + this->layout.getTypeSizeInBits(v->type) / 8) {
    return *v;
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
      impl(new DefaultCallableTypeProviderImpl(default_arch)) {}

// Set `decl` to the default callable type for `arch`.
void DefaultCallableTypeProvider::SetDefault(remill::ArchName arch,
                                             CallableDecl decl) {
  impl->decls[arch] = std::move(decl);
}

// Try to return the type of a function starting at address `address`. This
// type is the prototype of the function.
std::optional<FunctionDecl>
ProxyTypeProvider::TryGetFunctionType(uint64_t address) const {
  return this->deleg.TryGetFunctionType(address);
}

// Try to return the variable at given address or containing the address
std::optional<VariableDecl>
ProxyTypeProvider::TryGetVariableType(uint64_t address,
                                      llvm::Type *hinted_value_type) const {
  return this->deleg.TryGetVariableType(address, hinted_value_type);
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

std::optional<FunctionDecl>
TypeProvider::GetDefaultFunctionType(uint64_t address) const {
  return std::nullopt;
}

std::optional<VariableDecl>
TypeProvider::GetDefaultVariableDecl(uint64_t address) const {
  return std::nullopt;
}


std::optional<FunctionDecl>
TypeProvider::TryGetFunctionTypeOrDefault(uint64_t address) const {
  auto res = this->TryGetFunctionType(address);
  if (res.has_value()) {
    return res;
  }

  return this->GetDefaultFunctionType(address);
}

std::optional<VariableDecl>
TypeProvider::TryGetVariableTypeOrDefault(uint64_t address,
                                          llvm::Type *hinted_value_type) const {
  auto res = this->TryGetVariableType(address, hinted_value_type);
  if (res.has_value()) {
    return res;
  }

  return this->GetDefaultVariableDecl(address);
}


}  // namespace anvill
