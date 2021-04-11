/*
 * Copyright (c) 2021 Trail of Bits, Inc.
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

#include "ProgramMemoryProvider.h"

#include "../Program.h"

namespace anvill {

struct ProgramMemoryProvider::PrivateData final {
  PrivateData(const IProgram &program_)
      : program(static_cast<const Program &>(program_)) {}

  const Program &program;
};

ProgramMemoryProvider::ProgramMemoryProvider(const IProgram &program_)
    : d(new PrivateData(program_)) {}

std::tuple<uint8_t, ByteAvailability, BytePermission>
ProgramMemoryProvider::Query(uint64_t address) const {
  auto byte = d->program.FindByte(address);

  // TODO(pag): ANVILL specs don't communicate the structure of the address
  //            space, just the contents of a subset of the memory of the
  //            address space.
  if (!byte) {
    return {0, ByteAvailability::kUnknown, BytePermission::kUnknown};
  }

  uint8_t byte_out = byte.ValueOr(0u);
  auto perm_out = BytePermission::kUnknown;
  if (byte.IsWriteable() && byte.IsWriteable()) {
    perm_out = BytePermission::kReadableWritableExecutable;
  } else if (byte.IsWriteable()) {
    perm_out = BytePermission::kReadableWritable;
  } else if (byte.IsExecutable()) {
    perm_out = BytePermission::kReadableExecutable;
  } else {
    perm_out = BytePermission::kReadable;
  }

  return {byte_out, ByteAvailability::kAvailable, perm_out};
}

}  // namespace anvill
