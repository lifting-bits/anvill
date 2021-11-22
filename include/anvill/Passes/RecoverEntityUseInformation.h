/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <anvill/CrossReferenceFolder.h>
#include <anvill/EntityLifter.h>
#include <anvill/ValueLifter.h>
#include <anvill/Result.h>

#include <unordered_map>

#include "BaseFunctionPass.h"

namespace anvill {

class TypeProvider;

enum class EntityReferenceErrorCode {
  UnknownError,
};

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
class RecoverEntityUseInformation final
    : public BaseFunctionPass<RecoverEntityUseInformation> {

  // Entity lifter, used for lifting entities by declaration.
  const EntityLifter entity_lifter;

  // Address lifter, usef for lifting entities by address/type.
  const ValueLifter address_lifter;

  // Used for summarizing/folding values into possible referenced addresses.
  const CrossReferenceResolver xref_resolver;

 public:
  // Creates a new RecoverStackFrameInformation object
  static RecoverEntityUseInformation *
  Create(ITransformationErrorManager &error_manager,
         const EntityLifter &lifter);

  // Function pass entry point
  bool Run(llvm::Function &function, llvm::FunctionAnalysisManager &fam);

  // Returns the pass name
  static llvm::StringRef name(void);

  // Enumerates some of the possible entity usages that are isolated to
  // specific instruction operand uses.
  EntityUsages EnumeratePossibleEntityUsages(llvm::Function &function);

  // Patches the function, replacing the uses known to the entity lifter.
  Result<std::monostate, EntityReferenceErrorCode>
  UpdateFunction(llvm::Function &function, const EntityUsages &uses);

  RecoverEntityUseInformation(ITransformationErrorManager &error_manager,
                              const EntityLifter &lifter);

  virtual ~RecoverEntityUseInformation() override = default;
};

}  // namespace anvill
