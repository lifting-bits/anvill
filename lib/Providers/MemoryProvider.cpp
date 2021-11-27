/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Providers.h>

namespace anvill {

std::tuple<uint8_t, ByteAvailability, BytePermission>
NullMemoryProvider::Query(uint64_t address) const {
  return {0, ByteAvailability::kUnknown, BytePermission::kUnknown};
}

MemoryProvider::~MemoryProvider(void) {}

}  // namespace anvill
