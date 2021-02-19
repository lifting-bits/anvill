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

#pragma once

#include "EntityLifter.h"

#include <anvill/Providers/MemoryProvider.h>
#include <anvill/Providers/TypeProvider.h>

#include <remill/Arch/Arch.h>
#include <remill/BC/Util.h>

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

namespace anvill {

EntityLifterImpl::~EntityLifterImpl(void) {

}

EntityLifterImpl::EntityLifterImpl(
    const std::shared_ptr<MemoryProvider> &mem_provider_,
    const std::shared_ptr<TypeProvider> &type_provider_,
    const remill::Arch *arch_, llvm::Module &module_)
    : mem_provider(mem_provider_),
      type_provider(type_provider_),
      arch(arch_),
      module(module_),
      semantics_module(remill::LoadArchSemantics(arch_)),
      value_lifter(module_) {
  arch->PrepareModule(&module);
}

EntityLifter::~EntityLifter(void) {}

EntityLifter::EntityLifter(const std::shared_ptr<MemoryProvider> &mem_provider_,
                           const std::shared_ptr<TypeProvider> &type_provider_,
                           const remill::Arch *arch_, llvm::Module &module_)
    : impl(std::make_shared<EntityLifterImpl>(mem_provider_, type_provider_,
                                              arch_, module_)) {}

// Tries to lift the entity at `address` and return an `llvm::Function *`
// or `llvm::GlobalAlias *` relating to that address.
llvm::Constant *EntityLifter::TryLiftEntity(uint64_t address) const {
  auto ent_it = impl->entities.find(address);
  if (ent_it != impl->entities.end()) {
    return ent_it->second;
  }

  uint8_t byte = 0;
  BytePermission byte_perm = BytePermission::kUnknown;

  auto &context = impl->module.getContext();
  auto func_type = impl->type_provider.TryGetFunctionType(address);
  if (func_type) {

  }


  return nullptr;
//  auto [added, new_ent_it] = impl->entities.emplace();
}

}  // namespace anvill
