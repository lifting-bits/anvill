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

#include "ControlFlowProvider.h"

namespace anvill {

struct ControlFlowProvider::PrivateData final {
  PrivateData(const Program &program_) : program(program_) {}

  const Program &program;
};

ControlFlowProvider::ControlFlowProvider(const Program &program)
    : d(new PrivateData(program)) {}

ControlFlowProvider::~ControlFlowProvider(void) = default;

std::uint64_t ControlFlowProvider::GetRedirection(std::uint64_t address) const {
  std::uint64_t destination{};
  if (!d->program.GetControlFlowRedirection(destination, address)) {
    destination = address;
  }

  return destination;
}

Result<IControlFlowProvider::Ptr, ControlFlowProviderError>
IControlFlowProvider::Create(const Program &program) {
  try {
    return Ptr(new ControlFlowProvider(program));

  } catch (const std::bad_alloc &) {
    return ControlFlowProviderError::MemoryAllocationError;

  } catch (const ControlFlowProviderError &error) {
    return error;
  }
}
}  // namespace anvill
