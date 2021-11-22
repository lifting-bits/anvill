/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <anvill/TypeProvider.h>

namespace anvill {

class Program;

// Provider of memory wrapping around an `anvill::Program`.
class ProgramTypeProvider final : public TypeProvider {
 private:
  const Program &program;

 public:
  virtual ~ProgramTypeProvider(void);

  explicit ProgramTypeProvider(llvm::LLVMContext &context_,
                               const llvm::DataLayout &dl_,
                               const Program &program_);

  // Try to return the type of a function starting at address `address`. This
  // type is the prototype of the function.
  std::optional<FunctionDecl> TryGetFunctionType(
      uint64_t address) const final;

  std::optional<GlobalVarDecl>
  TryGetVariableType(uint64_t address) const final;

 private:
  ProgramTypeProvider(void) = delete;
};



}  // namespace anvill
