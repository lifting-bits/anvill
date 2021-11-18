/*
 * Copyright (c) 2021-present Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <anvill/Providers/ControlFlowProvider.h>

#include <anvill/Program.h>

#include <remill/Arch/Instruction.h>

namespace anvill {
namespace {

class ProgramControlFlowProvider final : public ControlFlowProvider {
 public:
  const Program &program;

  ProgramControlFlowProvider(const Program &program_)
      : program(program_) {}

  virtual ~ProgramControlFlowProvider(void) = default;

  std::uint64_t GetRedirection(
      const remill::Instruction &from_inst,
      std::uint64_t address) const final;

  std::optional<ControlFlowTargetList>
  TryGetControlFlowTargets(const remill::Instruction &from_inst) const final;
};

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

std::uint64_t ProgramControlFlowProvider::GetRedirection(
    const remill::Instruction &, std::uint64_t address) const {
  std::uint64_t destination = address;
  if (program.TryGetControlFlowRedirection(destination, address)) {
    return destination;
  } else {
    return address;
  }
}

std::optional<ControlFlowTargetList>
ProgramControlFlowProvider::TryGetControlFlowTargets(
    const remill::Instruction &from_inst) const {
  return program.TryGetControlFlowTargets(from_inst.pc);
}

}  // namespace

std::unique_ptr<ControlFlowProvider>
ControlFlowProvider::Create(const Program &program) {
  std::unique_ptr<ControlFlowProvider> ret(
      new ProgramControlFlowProvider(program));
  return ret;
}

// Create a dummy control-flow provider.
ControlFlowProvider::Ptr ControlFlowProvider::CreateNull(void) {
  std::unique_ptr<ControlFlowProvider> ret(
      new NullControlFlowProvider);
  return ret;
}

}  // namespace anvill
