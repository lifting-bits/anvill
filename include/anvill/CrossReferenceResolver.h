/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <cstdint>
#include <optional>

namespace llvm {
class Constant;
class Type;
}  // namespace llvm
namespace anvill {

class EntityLifter;
class EntityCrossReferenceResolverImpl;

// Cross-reference resolver interface.
class CrossReferenceResolver {
 public:
  virtual ~CrossReferenceResolver(void) = default;

  virtual std::optional<std::uint64_t> AddressOfEntity(
      llvm::Constant *ent) const = 0;

  // `value_type` represents the type of the data stored at `addr`. If it's
  // not a `nullptr`, then the return value's `getType()` will be an
  // `llvm::PointerType` whose element type is `value_type`.
  virtual llvm::Constant *EntityAtAddress(
      std::uint64_t addr, llvm::Type *value_type=nullptr,
      unsigned address_space=0u) const = 0;
};

// Default cross-reference resolver. Never resolves anything.
class NullCrossReferenceResolver : public CrossReferenceResolver {
 public:
  virtual ~NullCrossReferenceResolver(void) = default;

  std::optional<std::uint64_t> AddressOfEntity(
      llvm::Constant *ent) const override;

  llvm::Constant *EntityAtAddress(
      std::uint64_t addr, llvm::Type *value_type,
      unsigned address_space) const override;
};

// Resolve cross-references with an entity lifter.
class EntityCrossReferenceResolver : public CrossReferenceResolver {
 protected:
  std::unique_ptr<EntityCrossReferenceResolverImpl> impl;

 public:
  virtual ~EntityCrossReferenceResolver(void);
  explicit EntityCrossReferenceResolver(const EntityLifter &entity_lifter_);

  std::optional<std::uint64_t> AddressOfEntity(
      llvm::Constant *ent) const override;

  llvm::Constant *EntityAtAddress(
      std::uint64_t addr, llvm::Type *value_type,
      unsigned address_space) const override;
};

}  // namespace anvill
