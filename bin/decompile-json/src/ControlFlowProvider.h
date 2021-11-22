/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <anvill/ControlFlowProvider.h>

namespace anvill {

class Program;

class ProgramControlFlowProvider final : public ControlFlowProvider {
 private:
  const Program &program;

 public:
  virtual ~ProgramControlFlowProvider(void);

  explicit ProgramControlFlowProvider(const Program &program_);

  std::uint64_t GetRedirection(
      const remill::Instruction &from_inst,
      std::uint64_t address) const final;

  std::optional<ControlFlowTargetList>
  TryGetControlFlowTargets(const remill::Instruction &from_inst) const final;
};

}  // namespace anvill
