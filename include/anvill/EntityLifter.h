/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
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
class ValueLifter;
class ValueLifterImpl;

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
      const std::shared_ptr<::anvill::TypeProvider> &type_provider_);

  // Assuming that `entity` is an entity that was lifted by this `EntityLifter`,
  // then return the address of that entity in the binary being lifted.
  std::optional<uint64_t> AddressOfEntity(llvm::Constant *entity) const;

  // Return the options being used by this entity lifter.
  const LifterOptions &Options(void) const;

  // Return a reference to the memory provider used by this entity lifter.
  MemoryProvider &MemoryProvider(void) const;

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
