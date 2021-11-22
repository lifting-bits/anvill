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

#include <anvill/ControlFlowProvider.h>

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
