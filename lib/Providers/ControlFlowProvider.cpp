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

std::uint64_t NullControlFlowProvider::GetRedirection(
    const remill::Instruction &, std::uint64_t address,
    remill::ArchName) const {
  return address;
}

std::optional<ControlFlowTargetList>
NullControlFlowProvider::TryGetControlFlowTargets(
    const remill::Instruction &, remill::ArchName) const {
  return std::nullopt;
}


SpecificationControlFlowProvider::~SpecificationControlFlowProvider(void) {}

SpecificationControlFlowProvider::SpecificationControlFlowProvider(
    const Specification &spec)
      : impl(spec.impl) {}

std::uint64_t SpecificationControlFlowProvider::GetRedirection(
    const remill::Instruction &inst, std::uint64_t address,
    remill::ArchName to_arch) const {
  (void) to_arch;
  auto it = impl->redirections.find(inst.pc);
  if (it != impl->redirections.end()) {
    return it->second;
  } else {
    return address;
  }
}

std::optional<anvill::ControlFlowTargetList>
SpecificationControlFlowProvider::TryGetControlFlowTargets(
    const remill::Instruction &inst, remill::ArchName to_arch) const {
  (void) to_arch;
  auto it = impl->address_to_targets.find(inst.pc);
  if (it != impl->address_to_targets.end()) {
    return *(it->second);
  } else {
    return std::nullopt;
  }
}

}  // namespace anvill
