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

#include "Program/Program.h"
#include "Common/Result.h"

#include <memory>

namespace anvill {

enum class ControlFlowProviderError {
  MemoryAllocationError,
};

class ControlFlowProvider {
 public:
  using Ptr = std::unique_ptr<ControlFlowProvider>;

  static Result<Ptr, ControlFlowProviderError> Create(const Program &program);
  ~ControlFlowProvider(void);

  // Returns a possible redirection for the given target
  std::uint64_t GetRedirection(std::uint64_t address) const ;

  ControlFlowProvider(const ControlFlowProvider &) = delete;
  ControlFlowProvider(ControlFlowProvider &&) noexcept = delete;

  ControlFlowProvider &operator=(const ControlFlowProvider &) = delete;
  ControlFlowProvider &operator=(ControlFlowProvider &&) noexcept = delete;

 private:
   struct PrivateData;
   std::unique_ptr<PrivateData> d;

   ControlFlowProvider(const Program &program);
};

}  // namespace anvill
