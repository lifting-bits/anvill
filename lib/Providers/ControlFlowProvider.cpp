/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Providers.h>

#include <remill/Arch/Instruction.h>

namespace anvill {

std::uint64_t NullControlFlowProvider::GetRedirection(
    const remill::Instruction &, std::uint64_t address) const {
  return address;
}

std::optional<ControlFlowTargetList>
NullControlFlowProvider::TryGetControlFlowTargets(const remill::Instruction &) const {
  return std::nullopt;
}

}  // namespace anvill
