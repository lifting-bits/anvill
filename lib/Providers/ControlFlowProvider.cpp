/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Providers.h>
#include <remill/Arch/Instruction.h>

#include "Specification.h"

namespace anvill {

ControlFlowOverride NullControlFlowProvider::GetControlFlowOverride(uint64_t addr) const {
  return {};
}


SpecificationControlFlowProvider::~SpecificationControlFlowProvider(void) {}

SpecificationControlFlowProvider::SpecificationControlFlowProvider(
    const Specification &spec)
    : impl(spec.impl) {}

ControlFlowOverride SpecificationControlFlowProvider::GetControlFlowOverride(uint64_t addr) const {
  return impl->control_flow_overrides[addr];
}

}  // namespace anvill
