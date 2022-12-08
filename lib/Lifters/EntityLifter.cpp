/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "EntityLifter.h"

#include <anvill/Providers.h>
#include <glog/logging.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalAlias.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Transforms/Utils/ModuleUtils.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/Util.h>

#include <sstream>

#include "Lifters/FunctionLifter.h"

namespace anvill {

EntityLifterImpl::~EntityLifterImpl(void) {}

EntityLifterImpl::EntityLifterImpl(const LifterOptions &options_)
    : options(options_),
      memory_provider(&(options.memory_provider)),
      type_provider(&(options.type_provider)),
      value_lifter(options),
      function_lifter(FunctionLifter::CreateFunctionLifter(options_)),
      data_lifter(options) {
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
  if (auto [it, added] = entity_to_address.insert({entity, address}); added) {
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
    for (llvm::Value *gv : it->second) {
      if (gv && llvm::isa<llvm::Constant>(gv)) {
        cb(llvm::cast<llvm::Constant>(gv));
      }
    }
  }
}

EntityLifter::~EntityLifter(void) {}

EntityLifter::EntityLifter(const LifterOptions &options_)
    : impl(std::make_shared<EntityLifterImpl>(options_)) {}

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

// Return the data layout associated with this entity lifter.
const llvm::DataLayout &EntityLifter::DataLayout(void) const {
  return impl->options.DataLayout();
}

// Return a reference to the memory provider used by this entity lifter.
const ::anvill::MemoryProvider &EntityLifter::MemoryProvider(void) const {
  return *(impl->memory_provider);
}

// Return a reference to the type provider for this entity lifter.
const ::anvill::TypeProvider &EntityLifter::TypeProvider(void) const {
  return *(impl->type_provider);
}

}  // namespace anvill
