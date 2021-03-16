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

#pragma once

#include <cstdint>
#include <memory>
#include <tuple>

namespace anvill {

class Program;

enum class BytePermission : uint8_t {
  kUnknown,
  kReadable,
  kReadableWritable,
  kReadableWritableExecutable,
  kReadableExecutable
};

enum class ByteAvailability : uint8_t {

  // The address is valid, but a value for the byte is not available.
  kUnknown,

  // The address is not mapped in the address space.
  kUnavailable,

  // The address is mapped and the byte value is available.
  kAvailable
};

// Provides bytes of memory from some source.
class MemoryProvider {
 public:
  virtual ~MemoryProvider(void);

  inline static bool HasByte(ByteAvailability availability) {
    return ByteAvailability::kAvailable == availability;
  }

  inline static bool IsValidAddress(ByteAvailability availability) {
    switch (availability) {
      case ByteAvailability::kUnknown:
      case ByteAvailability::kAvailable: return true;
      default: return false;
    }
  }

  inline static bool IsExecutable(BytePermission perms) {
    switch (perms) {
      case BytePermission::kUnknown:
      case BytePermission::kReadableWritableExecutable:
      case BytePermission::kReadableExecutable: return true;
      default: return false;
    }
  }

  // Query for the value, availability, and permission of a byte.
  virtual std::tuple<uint8_t, ByteAvailability, BytePermission>
  Query(uint64_t address) = 0;

  // Sources bytes from an `anvill::Program`.
  static std::shared_ptr<MemoryProvider>
  CreateProgramMemoryProvider(const Program &program);

  // Creates a memory provider that gives access to no memory.
  static std::shared_ptr<MemoryProvider> CreateNullMemoryProvider(void);

 protected:
  MemoryProvider(void) = default;

 private:
  MemoryProvider(const MemoryProvider &) = delete;
  MemoryProvider(MemoryProvider &&) noexcept = delete;
  MemoryProvider &operator=(const MemoryProvider &) = delete;
  MemoryProvider &operator=(MemoryProvider &&) noexcept = delete;
};

}  // namespace anvill
