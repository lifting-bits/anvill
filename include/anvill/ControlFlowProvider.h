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

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace remill {
class Instruction;
}  // namespace remill
namespace anvill {

// Describes a list of targets reachable from a given source address
struct ControlFlowTargetList final {

  // Source address
  std::uint64_t source{};

  // Destination list
  std::vector<std::uint64_t> destination_list;

  // True if this destination list appears to be complete. As a
  // general rule, this is set to true when the target recovery has
  // been completely performed by the disassembler tool
  bool complete{false};
};

class ControlFlowProvider {
 public:
  using Ptr = std::unique_ptr<ControlFlowProvider>;

  // Create a dummy control-flow provider.
  static Ptr CreateNull(void);

  virtual ~ControlFlowProvider(void) = default;

  // Returns a possible redirection for the given target. If there is no
  // redirection then `address` should be returned.
  virtual std::uint64_t GetRedirection(
      const remill::Instruction &from_inst, std::uint64_t to_address) const = 0;

  // Returns a list of targets reachable from the given address
  virtual std::optional<ControlFlowTargetList>
  TryGetControlFlowTargets(const remill::Instruction &from_inst) const = 0;

 protected:
  ControlFlowProvider(void) = default;

 private:
  ControlFlowProvider(const ControlFlowProvider &) = delete;
  ControlFlowProvider(ControlFlowProvider &&) noexcept = delete;

  ControlFlowProvider &operator=(const ControlFlowProvider &) = delete;
  ControlFlowProvider &operator=(ControlFlowProvider &&) noexcept = delete;
};

}  // namespace anvill
