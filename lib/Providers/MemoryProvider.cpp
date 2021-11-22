/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/MemoryProvider.h>

namespace anvill {
namespace {

class NullMemoryProvider final : public MemoryProvider {
 public:
  std::tuple<uint8_t, ByteAvailability, BytePermission>
  Query(uint64_t address) const final {
    return {0, ByteAvailability::kUnknown, BytePermission::kUnknown};
  }
};

}  // namespace

MemoryProvider::~MemoryProvider(void) {}

// Creates a memory provider that gives access to no memory.
std::shared_ptr<MemoryProvider> MemoryProvider::CreateNull(void) {
  return std::make_shared<NullMemoryProvider>();
}

}  // namespace anvill
