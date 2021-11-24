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
namespace {

class NullControlFlowProvider final : public ControlFlowProvider {
 public:

  NullControlFlowProvider(void) = default;

  virtual ~NullControlFlowProvider(void) = default;

  std::uint64_t GetRedirection(
      const remill::Instruction &, std::uint64_t address) const final {
    return address;
  }

  std::optional<ControlFlowTargetList>
  TryGetControlFlowTargets(const remill::Instruction &) const final {
    return std::nullopt;
  }
};

}  // namespace

// Create a dummy control-flow provider.
ControlFlowProvider::Ptr ControlFlowProvider::CreateNull(void) {
  std::unique_ptr<ControlFlowProvider> ret(
      new NullControlFlowProvider);
  return ret;
}

}  // namespace anvill
