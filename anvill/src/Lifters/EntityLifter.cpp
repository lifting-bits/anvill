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

#include <remill/Arch/Arch.h>
#include <remill/BC/Util.h>

#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalAlias.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include <sstream>

#include <glog/logging.h>

namespace anvill {

EntityLifterImpl::~EntityLifterImpl(void) {}

EntityLifterImpl::EntityLifterImpl(
    const LifterOptions &options_,
    const std::shared_ptr<MemoryProvider> &mem_provider_,
    const std::shared_ptr<TypeProvider> &type_provider_)
    : options(options_),
      memory_provider(mem_provider_),
      type_provider(type_provider_),
      value_lifter(options),
      function_lifter(options, *mem_provider_, *type_provider_) {
  CHECK_EQ(options.arch->context, &(options.module->getContext()));
  options.arch->PrepareModule(options.module);
}

// Tries to lift the data at `address` and return an `llvm::GlobalAlias *`.
//
// A key issue with `TryLiftData` is that we might be requesting `address`,
// but `address` may be inside of another piece of data, which begins
// at `data_address`.
llvm::Constant *EntityLifterImpl::TryLiftData(
    uint64_t address, uint64_t data_address, llvm::Type *data_type) {
  auto &context = options.module->getContext();
  data_type = remill::RecontextualizeType(data_type, context);

  std::stringstream ss;
  ss << "data_" << std::hex << data_address;
  const auto ref_name = ss.str();

//  auto alias = llvm::GlobalAlias
  return nullptr;
}

EntityLifter::~EntityLifter(void) {}

EntityLifter::EntityLifter(const LifterOptions &options_,
                           const std::shared_ptr<MemoryProvider> &mem_provider_,
                           const std::shared_ptr<TypeProvider> &type_provider_)
    : impl(std::make_shared<EntityLifterImpl>(
          options_, mem_provider_, type_provider_)) {}

// Tries to lift the entity at `address` and return an `llvm::Function *`
// or `llvm::GlobalAlias *` relating to that address.
llvm::Constant *EntityLifter::TryLiftEntity(uint64_t address) const {
  auto ent_it = impl->entities.find(address);
  if (ent_it != impl->entities.end()) {
    return ent_it->second;
  }

  auto [byte, availability, permission] =
      impl->memory_provider->Query(address);

  switch (availability) {
    case ByteAvailability::kUnknown:
    case ByteAvailability::kAvailable:
      break;

    // If the byte isn't available, then it's not part of the address space
    // to which the memory provider provides access.
    case ByteAvailability::kUnavailable:
      return nullptr;
  }

  llvm::Constant *ret = nullptr;

  switch (permission) {
    case BytePermission::kUnknown:
    case BytePermission::kReadableExecutable:
    case BytePermission::kReadableWritableExecutable:
      if (auto maybe_decl = impl->type_provider->TryGetFunctionType(address);
          maybe_decl) {
        ret = impl->function_lifter.LiftFunction(*maybe_decl);
        break;
      }
      [[clang::fallthrough]];
    case BytePermission::kReadable:
    case BytePermission::kReadableWritable: {

    }
  }

  auto [new_ent_it, added] = impl->entities.emplace(address, ret);
  if (added) {
    impl->new_entities.emplace_back(address, ret);
  }

  return ret;
}

}  // namespace anvill
