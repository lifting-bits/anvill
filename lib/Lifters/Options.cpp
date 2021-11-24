/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Lifter.h>
#include <anvill/Type.h>
#include <glog/logging.h>
#include <llvm/IR/Module.h>
#include <remill/Arch/Arch.h>

namespace anvill {

void LifterOptions::CheckModuleContextMatchesArch(void) const {
  CHECK_EQ(&(module->getContext()), arch->context);
}

// Return the data layout associated with the lifter options.
const llvm::DataLayout &LifterOptions::DataLayout(void) const {
  return module->getDataLayout();
}

// Dictionary of types to be used by the type specifier. Any time we load
// or store types into memory, we may be operating on wrapped types, e.g.
// a structure wrapping an `i32`, signalling that we're actually dealing with
// a signed integer. To know what is what, we need to know the dictionary of
// interpretable types.
const ::anvill::TypeDictionary &LifterOptions::TypeDictionary(void) const {
  return type_provider.Dictionary();
}

}  // namespace anvill
