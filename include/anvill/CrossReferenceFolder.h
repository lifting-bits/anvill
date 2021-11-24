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
#include <memory>

namespace llvm {
class Constant;
class DataLayout;
class Type;
class Value;
}  // namespace llvm
namespace anvill {

class CrossReferenceFolderImpl;
class CrossReferenceResolver;
class EntityLifter;

struct ResolvedCrossReference {
  union {

    // The interpreted version of the address.
    std::uint64_t address;

    // In the case of a stack pointer reference, we're generally dealing with a
    // displacement and not a concrete address.
    //
    // Prefer to use ResolvedCrossReference::Displacement instead of accessing
    // this field directly, since this value needs to be adjusted according
    // to the size of a pointer
    std::int64_t displacement;
  } u;

  // As we're visiting a constant/cross-reference, we may encounter a symbolic
  // type hint, which takes the form of `__anvill_type_XYZ`. These exist to
  // funnel higher-level type information (provided by a tool such as Binary
  // Ninja or IDA Pro) through the lifting pipeline.
  //
  // Similarly, if we encounter a global variable then we'll include its type
  // information in the `hinted_type`.
  //
  // Type hint priority is based on depth; we retain the shallowest hinted types
  // in constant expression trees. In some cases, e.g. an `add` with both
  // operands being hinted, we drop the type hints.
  llvm::Type *hinted_value_type{nullptr};

  // size of the operand that is used to adjust the displacement of references
  unsigned size{0};

  // If we have a `hinted_type`, then how "far away" are we from that hinted
  // type? I.e. we might be doing a `getelementptr` on a pointer that is type
  // hinted, and so this represents the displacement induced by the GEP indices.
  std::int64_t displacement_from_hinted_value_type{0};

  // Saturating facts about what we've encountered in the process of evaluating
  // and trying to resolve a cross-reference.

  // Whether or not an entity known to the `EntityLifter` was referenced. This
  // is a good signal that `u.address` is an address.
  bool references_entity : 1;

  // Whether or not a global value was referenced. This usually means we came
  // across an `llvm::GlobalVariable`, `llvm::GlobalAlias`, or `llvm::Function`.
  // This doesn't imply that the found value is a known entity.
  bool references_global_value : 1;

  // Whether or not we observed the stack pointer being used in the computation
  // of `u.displacement`.
  bool references_stack_pointer : 1;

  // Whether or not we observed the program counter being used in the
  // computation of `u.address`.
  bool references_program_counter : 1;

  // Whether or not we observed the return address being used in the computation
  // of `u.displacement`.
  bool references_return_address : 1;

  // Was folding successful or not?
  bool is_valid : 1;

  // Returns `true` if the resolution appears valid.
  inline operator bool(void) const {
    return is_valid;
  }

  // Returns the displacement value, adjusted according to operand size
  std::int64_t Displacement(const llvm::DataLayout &dl) const;
};

// Attempts to fold cross-references down into their intended addresses. This
// class maintains an internal cache of prior resolved cross-references. An
// internal cache of prior foldings is maintained, as the mechanism by which
// Anvill lifts cross-references is via "tainted" constant expressions, which
// are likely to be "pushed around" by LLVM's optimizatons (const prop/folding)
// and accumulated into increasingly larger expressions. Thus, we expect that
// multiple instructions/constant expressions will reference the same underlying
// expressions.
class CrossReferenceFolder {
 public:
  ~CrossReferenceFolder(void);

  // Create a new
  explicit CrossReferenceFolder(const CrossReferenceResolver &resolver,
                                const llvm::DataLayout &dl);

  // Return a reference to the data layout used by the cross-reference folder.
  const llvm::DataLayout &DataLayout(void) const;

  // Clear the internal cache.
  void ClearCache(void) const;

  // Try to resolve `val` as a cross-reference with xrefs caching
  ResolvedCrossReference TryResolveReferenceWithCaching(llvm::Value *val) const;

  // Try to resolve `val` as a cross-reference with cleared xrefs cache
  ResolvedCrossReference
  TryResolveReferenceWithClearedCache(llvm::Value *val) const;

  // Returns the "magic" value that represents the return address.
  uint64_t MagicReturnAddressValue(void) const;

  CrossReferenceFolder(const CrossReferenceFolder &) = default;
  CrossReferenceFolder(CrossReferenceFolder &&) noexcept = default;
  CrossReferenceFolder &operator=(const CrossReferenceFolder &) = default;
  CrossReferenceFolder &
  operator=(CrossReferenceFolder &&) noexcept = default;

 private:
  CrossReferenceFolder(void) = delete;

  std::shared_ptr<CrossReferenceFolderImpl> impl;
};

}  // namespace anvill
