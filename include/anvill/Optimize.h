/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <anvill/Specification.h>

#include "anvill/Passes/BasicBlockPass.h"

namespace llvm {
class Module;
}  // namespace llvm
namespace remill {
class Arch;
}  // namespace remill

namespace anvill {

class EntityLifter;

// Optimize a module. This can be a module with semantics code, lifted
// code, etc.
void OptimizeModule(const EntityLifter &lifter_context, llvm::Module &module,
                    const BasicBlockContexts &contexts,
                    const anvill::Specification &spec);

}  // namespace anvill
