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

#include <anvill/Program.h>
#include <anvill/Providers/MemoryProvider.h>

namespace anvill {
namespace {

// Provider of memory wrapping around an `anvill::Program`.
class ProgramMemoryProvider final : public MemoryProvider {
 public:
  explicit ProgramMemoryProvider(const Program &program_) : program(program_) {}

  std::tuple<uint8_t, ByteAvailability, BytePermission>
  Query(uint64_t address) final {
    auto byte = program.FindByte(address);

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

 private:
  ProgramMemoryProvider(void) = delete;

  const Program &program;
};


class NullMemoryProvider final : public MemoryProvider {
 public:
  std::tuple<uint8_t, ByteAvailability, BytePermission>
  Query(uint64_t address) final {
    return {0, ByteAvailability::kUnknown, BytePermission::kUnknown};
  }
};

}  // namespace

MemoryProvider::~MemoryProvider(void) {}

// Sources bytes from an `anvill::Program`.
std::shared_ptr<MemoryProvider>
MemoryProvider::CreateProgramMemoryProvider(const Program &program) {
  return std::make_shared<ProgramMemoryProvider>(program);
}

// Creates a memory provider that gives access to no memory.
std::shared_ptr<MemoryProvider>
MemoryProvider::CreateNullMemoryProvider(void) {
  return std::make_shared<NullMemoryProvider>();
}

}  // namespace anvill
