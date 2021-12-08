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
class Function;
class GlobalValue;
class Module;
}  // namespace llvm
namespace remill {
class Arch;
}  // namespace remill
namespace anvill {

struct FunctionDecl;
struct GlobalVarDecl;

class EntityLifterImpl;
class FunctionLifter;
class LifterOptions;
class MemoryProvider;
class TypeProvider;
class FunctionPrototypeProvider;
class ValueLifter;
class ValueLifterImpl;
class Program;

// Lifting context for ANVILL. The lifting context keeps track of the options
// used for lifting, the module into which lifted objects are placed, and
// a the mapping between lifted objects and their original addresses in the
// binary.
class EntityLifter {
 public:
  ~EntityLifter(void);

  explicit EntityLifter(
      const LifterOptions &options,
      const std::shared_ptr<MemoryProvider> &mem_provider_,
      const std::shared_ptr<::anvill::TypeProvider> &type_provider_, const FunctionPrototypeProvider&);

  // Assuming that `entity` is an entity that was lifted by this `EntityLifter`,
  // then return the address of that entity in the binary being lifted.
  std::optional<uint64_t> AddressOfEntity(llvm::Constant *entity) const;

  // Return the options being used by this entity lifter.
  const LifterOptions &Options(void) const;

  // Return a reference to the type provider for this entity lifter.
  TypeProvider &TypeProvider(void) const;

  // Lift a function and return it. Returns `nullptr` if there was a failure.
  llvm::Function *LiftEntity(const FunctionDecl &decl) const;

  // Lift a function and return it. Returns `nullptr` if there was a failure.
  llvm::Function *DeclareEntity(const FunctionDecl &decl) const;

  // Lift a variable and return it. Returns `nullptr` if there was a failure.
  llvm::Constant *LiftEntity(const GlobalVarDecl &decl) const;

  // Lift a variable and return it. Returns `nullptr` if there was a failure.
  llvm::Constant *DeclareEntity(const GlobalVarDecl &decl) const;

  EntityLifter(const EntityLifter &) = default;
  EntityLifter(EntityLifter &&) noexcept = default;
  EntityLifter &operator=(const EntityLifter &) = default;
  EntityLifter &operator=(EntityLifter &&) noexcept = default;

 private:
  friend class DataLifter;
  friend class FunctionLifter;
  friend class ValueLifter;
  friend class ValueLifterImpl;

  inline EntityLifter(const std::shared_ptr<EntityLifterImpl> &impl_)
      : impl(impl_) {}

  EntityLifter(void) = default;

  std::shared_ptr<EntityLifterImpl> impl;
};

}  // namespace anvill
