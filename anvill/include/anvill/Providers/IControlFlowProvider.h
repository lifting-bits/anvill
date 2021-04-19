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

#include <anvill/Program.h>
#include <anvill/Result.h>

#include <memory>
#include <optional>

namespace anvill {

enum class ControlFlowProviderError {
  MemoryAllocationError,
};

class IControlFlowProvider {
 public:
  using Ptr = std::unique_ptr<IControlFlowProvider>;

  static Result<Ptr, ControlFlowProviderError> Create(const Program &program);
  virtual ~IControlFlowProvider(void) = default;

  // Returns a possible redirection for the given target
  virtual std::uint64_t GetRedirection(std::uint64_t address) const = 0;

  // Returns a list of targets reachable from the given address
  virtual std::optional<ControlFlowTargetList>
  TryGetControlFlowTargets(std::uint64_t address) const = 0;

 protected:
  IControlFlowProvider(void) = default;

 private:
  IControlFlowProvider(const IControlFlowProvider &) = delete;
  IControlFlowProvider(IControlFlowProvider &&) noexcept = delete;

  IControlFlowProvider &operator=(const IControlFlowProvider &) = delete;
  IControlFlowProvider &operator=(IControlFlowProvider &&) noexcept = delete;
};

}  // namespace anvill
