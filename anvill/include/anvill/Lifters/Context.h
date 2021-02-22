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

#include <cstdint>
#include <memory>
#include <optional>

namespace llvm {
class Constant;
class GlobalValue;
class Module;
}  // namespace llvm
namespace remill {
class Arch;
}  // namespace remill
namespace anvill {

class ContextImpl;
class FunctionLifter;
class LifterOptions;
class MemoryProvider;
class TypeProvider;
class ValueLifter;

// Lifting context for ANVILL. The lifting context keeps track of the options
// used for lifting, the module into which lifted objects are placed, and
// a the mapping between lifted objects and their original addresses in the
// binary.
class Context {
 public:
  ~Context(void);

  explicit Context(const LifterOptions &options,
                   const std::shared_ptr<MemoryProvider> &mem_provider_,
                   const std::shared_ptr<TypeProvider> &type_provider_);

  // Assuming that `entity` is an entity that was lifted by this `EntityLifter`,
  // then return the address of that entity in the binary being lifted.
  std::optional<uint64_t> AddressOfEntity(llvm::GlobalValue *entity) const;

  // Return the options being used by this entity lifter.
  const LifterOptions &Options(void) const;

  Context(const Context &) = default;
  Context(Context &&) noexcept = default;
  Context &operator=(const Context &) = default;
  Context &operator=(Context &&) noexcept = default;

 private:
  friend class DataLifter;
  friend class FunctionLifter;
  friend class ValueLifter;

  inline Context(const std::shared_ptr<ContextImpl> &impl_)
      : impl(impl_) {}

  Context(void) = default;

  std::shared_ptr<ContextImpl> impl;
};

}  // namespace anvill
