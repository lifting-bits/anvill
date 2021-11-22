/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "MemoryProvider.h"

#include "Program.h"

namespace anvill {

ProgramMemoryProvider::~ProgramMemoryProvider(void) {}

ProgramMemoryProvider::ProgramMemoryProvider(const Program &program_)
      : program(program_) {}

std::tuple<uint8_t, ByteAvailability, BytePermission>
ProgramMemoryProvider::Query(uint64_t address) const {
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

}  // namespace anvill
