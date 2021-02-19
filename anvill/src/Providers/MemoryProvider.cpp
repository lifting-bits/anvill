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

#include <anvill/Providers/MemoryProvider.h>

#include <anvill/Program.h>

namespace anvill {
namespace {

// Provider of memory wrapping around an `anvill::Program`.
class ProgramMemoryProvider final : public MemoryProvider {
 public:

  virtual ~ProgramMemoryProvider(void) = default;

  explicit ProgramMemoryProvider(const Program &program_)
      : program(program_) {}

  ByteAvailability TryReadByte(uint64_t address, uint8_t *byte_out,
                               BytePermission *perm_out) final {
    auto byte = program.FindByte(address);

    // TODO(pag): This is only correct half the time. ANVILL specs don't
    //            communicate the structure of the address space, just the
    //            contents of a subset of the memory of the address space.
    if (!byte) {
      *perm_out = BytePermission::kReadableWritableExecutable;
      return ByteAvailability::kAvailableButNotDefined;
    }

    *byte_out = byte.ValueOr(0u);
    if (byte.IsWriteable() && byte.IsWriteable()) {
      *perm_out = BytePermission::kReadableWritableExecutable;
    } else if (byte.IsWriteable()) {
      *perm_out = BytePermission::kReadableWritable;
    } else if (byte.IsExecutable()) {
      *perm_out = BytePermission::kReadableExecutable;
    } else {
      *perm_out = BytePermission::kReadable;
    }

    return ByteAvailability::kAvailable;
  }

 private:
  ProgramMemoryProvider(void) = delete;

  const Program &program;
};

}  // namespace

MemoryProvider::~MemoryProvider(void) {}

// Sources bytes from an `anvill::Program`.
std::shared_ptr<MemoryProvider> MemoryProvider::CreateProgramMemoryProvider(
    const Program &program) {
  return std::make_shared<ProgramMemoryProvider>(program);
}

}  // namespace anvill
