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

#include <anvill/IProgram.h>

#include <cstdint>
#include <memory>
#include <tuple>

namespace anvill {

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
class IMemoryProvider {
 public:
  using Ptr = std::unique_ptr<IMemoryProvider>;

  static Ptr CreateFromProgram(const IProgram &program);
  static Ptr CreateNull();

  virtual ~IMemoryProvider(void) = default;
  IMemoryProvider(void) = default;

  // Query for the value, availability, and permission of a byte.
  virtual std::tuple<uint8_t, ByteAvailability, BytePermission>
  Query(uint64_t address) const = 0;

  IMemoryProvider(const IMemoryProvider &) = delete;
  IMemoryProvider(IMemoryProvider &&) noexcept = delete;

  IMemoryProvider &operator=(const IMemoryProvider &) = delete;
  IMemoryProvider &operator=(IMemoryProvider &&) noexcept = delete;
};

}  // namespace anvill
