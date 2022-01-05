/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Providers.h>

#include "Specification.h"

namespace anvill {

std::tuple<uint8_t, ByteAvailability, BytePermission>
NullMemoryProvider::Query(uint64_t address) const {
  return {0, ByteAvailability::kUnknown, BytePermission::kUnknown};
}

MemoryProvider::~MemoryProvider(void) {}


SpecificationMemoryProvider::~SpecificationMemoryProvider(void) {}

SpecificationMemoryProvider::SpecificationMemoryProvider(
    const Specification &spec)
      : impl(spec.impl) {}

std::tuple<uint8_t, anvill::ByteAvailability, anvill::BytePermission>
SpecificationMemoryProvider::Query(uint64_t address) const {
  auto byte_it = impl->memory.find(address);

  // TODO(pag): ANVILL specs don't communicate the structure of the address
  //            space, just the contents of a subset of the memory of the
  //            address space.
  if (byte_it == impl->memory.end()) {
    return {{}, anvill::ByteAvailability::kUnknown,
            anvill::BytePermission::kUnknown};
  } else {
    return {byte_it->second.first, anvill::ByteAvailability::kAvailable,
            byte_it->second.second};
  }
}


}  // namespace anvill
