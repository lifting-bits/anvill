/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <anvill/TypeProvider.h>

namespace decompile {

class Program;

// Provides the types of functions, called functions, and accessed data.
class ProgramTypeProvider final : public anvill::TypeProvider {
 private:
  const Program &program;

 public:
  virtual ~ProgramTypeProvider(void);

  explicit ProgramTypeProvider(const Program &program_,
                               const ::anvill::TypeTranslator &tt);

  // Try to return the type of a function starting at address `address`. This
  // type is the prototype of the function.
  std::optional<anvill::FunctionDecl> TryGetFunctionType(
      uint64_t address) const final;

  std::optional<anvill::GlobalVarDecl>
  TryGetVariableType(uint64_t address) const final;

 private:
  ProgramTypeProvider(void) = delete;
};

}  // namespace decompile
