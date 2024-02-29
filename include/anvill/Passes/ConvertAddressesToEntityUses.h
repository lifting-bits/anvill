/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <anvill/CrossReferenceFolder.h>
#include <llvm/IR/PassManager.h>

#include <optional>
#include <vector>

namespace llvm {
class Use;
}  // namespace llvm
namespace anvill {

class TypeProvider;

// Describes an instruction that appears to reference some entity.
struct EntityUse final {
  inline explicit EntityUse(llvm::Use *use_, ResolvedCrossReference xref_)
      : use(use_),
        xref(xref_) {}

  // An operand inside of a particular instruction, where `use->getUser()`
  // is an `llvm::Instruction`, and `use->get()` is a value related to the
  // stack pointer.
  llvm::Use *const use;

  // Resolved cross-reference.
  const ResolvedCrossReference xref;
};

// Contains a list of instruction operand uses that could feasibly be
// entity references.
using EntityUsages = std::vector<EntityUse>;

// This function pass recovers stack information by analyzing the usage
// of the `__anvill_sp` symbol
class ConvertAddressesToEntityUses final
    : public llvm::PassInfoMixin<ConvertAddressesToEntityUses> {
 private:
  // Resolve addresses to entities and vice versa.
  const CrossReferenceResolver &xref_resolver;

  // The metadata ID to annotation recovered entities with.
  const std::optional<unsigned> pc_metadata_id;

 public:
  // Function pass entry point
  llvm::PreservedAnalyses run(llvm::Function &function,
                              llvm::FunctionAnalysisManager &fam);

  // Returns the pass name
  static llvm::StringRef name(void);

  bool IsPointerLike(llvm::Use &use);

  // Enumerates some of the possible entity usages that are isolated to
  // specific instruction operand uses.
  EntityUsages EnumeratePossibleEntityUsages(llvm::Function &function);

  ConvertAddressesToEntityUses(
      const CrossReferenceResolver &xref_resolver_,
      std::optional<unsigned> pc_metadata_id_ = std::nullopt);
};

}  // namespace anvill
