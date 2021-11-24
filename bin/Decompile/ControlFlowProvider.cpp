/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "ControlFlowProvider.h"

#include <remill/Arch/Instruction.h>

#include "Program.h"

namespace decompile {

ProgramControlFlowProvider::~ProgramControlFlowProvider(void) {}

ProgramControlFlowProvider::ProgramControlFlowProvider(const Program &program_)
      : program(program_) {}

std::uint64_t ProgramControlFlowProvider::GetRedirection(
    const remill::Instruction &, std::uint64_t address) const {
  std::uint64_t destination = address;
  if (program.TryGetControlFlowRedirection(destination, address)) {
    return destination;
  } else {
    return address;
  }
}

std::optional<anvill::ControlFlowTargetList>
ProgramControlFlowProvider::TryGetControlFlowTargets(
    const remill::Instruction &from_inst) const {
  return program.TryGetControlFlowTargets(from_inst.pc);
}

}  // namespace decompile
