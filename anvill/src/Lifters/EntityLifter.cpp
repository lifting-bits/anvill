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

#include "EntityLifter.h"

#include <anvill/Providers/MemoryProvider.h>
#include <anvill/Providers/TypeProvider.h>
#include <glog/logging.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalAlias.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Transforms/Utils/ModuleUtils.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/Util.h>

#include <sstream>

namespace anvill {

EntityLifterImpl::~EntityLifterImpl(void) {}

EntityLifterImpl::EntityLifterImpl(
    const LifterOptions &options_,
    const std::shared_ptr<MemoryProvider> &mem_provider_,
    const std::shared_ptr<TypeProvider> &type_provider_,
    const Program &program)
    : options(options_),
      memory_provider(mem_provider_),
      type_provider(type_provider_),
      value_lifter(options),
      function_lifter(options, *mem_provider_, *type_provider_, program),
      data_lifter(options, *mem_provider_, *type_provider_) {
  CHECK_EQ(options.arch->context, &(options.module->getContext()));
  options.arch->PrepareModule(options.module);
}

// Tells the entity lifter that `entity` is the lifted function/data at
// `address`. There is some collusion between the `Context`, the
// `FunctionLifter`, the `DataLifter`, and the `ValueLifter` to ensure their
// view of the world remains consistent.
void EntityLifterImpl::AddEntity(llvm::Constant *entity, uint64_t address) {
  CHECK_NOTNULL(entity);
  address_to_entity[address].insert(entity);
  if (auto [it, added] = entity_to_address.emplace(entity, address); added) {
    if (auto gv = llvm::dyn_cast<llvm::GlobalValue>(entity); gv) {
      llvm::GlobalValue *used[] = {gv};
      llvm::appendToCompilerUsed(*(options.module), used);
    }
  }
}

// Assuming that `entity` is an entity that was lifted by this `EntityLifter`,
// then return the address of that entity in the binary being lifted.
std::optional<uint64_t>
EntityLifterImpl::AddressOfEntity(llvm::Constant *entity) const {
  CHECK_NOTNULL(entity);
  auto it = entity_to_address.find(entity);
  if (it == entity_to_address.end()) {
    return std::nullopt;
  } else {
    return it->second;
  }
}

// Applies a callback `cb` to each entity at a specified address.
void EntityLifterImpl::ForEachEntityAtAddress(
    uint64_t address, std::function<void(llvm::Constant *)> cb) const {
  if (auto it = address_to_entity.find(address);
      it != address_to_entity.end()) {
    for (auto gv : it->second) {
      cb(gv);
    }
  }
}

EntityLifter::~EntityLifter(void) {}

EntityLifter::EntityLifter(
    const LifterOptions &options_,
    const std::shared_ptr<MemoryProvider> &mem_provider_,
    const std::shared_ptr<::anvill::TypeProvider> &type_provider_,
    const Program &program)
    : impl(std::make_shared<EntityLifterImpl>(options_, mem_provider_,
                                              type_provider_,
                                              program)) {}

// Assuming that `entity` is an entity that was lifted by this `EntityLifter`,
// then return the address of that entity in the binary being lifted.
std::optional<uint64_t>
EntityLifter::AddressOfEntity(llvm::Constant *entity) const {
  return impl->AddressOfEntity(entity);
}

// Return the options being used by this entity lifter.
const LifterOptions &EntityLifter::Options(void) const {
  return impl->options;
}

// Return a reference to the type provider for this entity lifter.
TypeProvider &EntityLifter::TypeProvider(void) const {
  return *(impl->type_provider);
}

}  // namespace anvill
