/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/LifterOptions.h>
#include <glog/logging.h>
#include <llvm/IR/Module.h>
#include <remill/Arch/Arch.h>

namespace anvill {

void LifterOptions::CheckModuleContextMatchesArch(void) const {
  CHECK_EQ(&(module->getContext()), arch->context);
}

}  // namespace anvill
