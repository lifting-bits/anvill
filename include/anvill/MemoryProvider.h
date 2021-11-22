/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <tuple>

namespace anvill {

enum class BytePermission : std::uint8_t {
  kUnknown,
  kReadable,
  kReadableWritable,
  kReadableWritableExecutable,
  kReadableExecutable
};

enum class ByteAvailability : std::uint8_t {

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
  virtual std::tuple<std::uint8_t, ByteAvailability, BytePermission>
  Query(std::uint64_t address) const = 0;

  // Creates a memory provider that gives access to no memory.
  static std::shared_ptr<MemoryProvider> CreateNull(void);

 protected:
  MemoryProvider(void) = default;

 private:
  MemoryProvider(const MemoryProvider &) = delete;
  MemoryProvider(MemoryProvider &&) noexcept = delete;
  MemoryProvider &operator=(const MemoryProvider &) = delete;
  MemoryProvider &operator=(MemoryProvider &&) noexcept = delete;
};

}  // namespace anvill
