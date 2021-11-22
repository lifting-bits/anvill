/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <anvill/MemoryProvider.h>

namespace anvill {

class Program;

// Provider of memory wrapping around an `anvill::Program`.
class ProgramMemoryProvider final : public MemoryProvider {
 public:
  virtual ~ProgramMemoryProvider(void);

  explicit ProgramMemoryProvider(const Program &program_);

  std::tuple<uint8_t, ByteAvailability, BytePermission>
  Query(uint64_t address) const final;

 private:
  ProgramMemoryProvider(void) = delete;

  const Program &program;
};


}  // namespace anvill
