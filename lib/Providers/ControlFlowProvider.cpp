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

std::uint64_t
NullControlFlowProvider::GetCallRedirection(std::uint64_t target) const {
  return target;
}

std::optional<ControlFlowTargetList>
NullControlFlowProvider::TryGetControlFlowTargets(
    const remill::Instruction &) const {
  return std::nullopt;
}


SpecificationControlFlowProvider::~SpecificationControlFlowProvider(void) {}

SpecificationControlFlowProvider::SpecificationControlFlowProvider(
    const Specification &spec)
    : impl(spec.impl) {}

std::uint64_t SpecificationControlFlowProvider::GetCallRedirection(
    std::uint64_t target) const {
  auto it = impl->redirections.find(target);
  if (it != impl->redirections.end()) {
    return it->second;
  } else {
    return target;
  }
}

std::optional<anvill::ControlFlowTargetList>
SpecificationControlFlowProvider::TryGetControlFlowTargets(
    const remill::Instruction &inst) const {
  auto it = impl->address_to_targets.find(inst.pc);
  if (it != impl->address_to_targets.end()) {
    return *(it->second);
  } else {
    return std::nullopt;
  }
}

}  // namespace anvill
