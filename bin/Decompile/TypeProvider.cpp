/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "TypeProvider.h"

#include <glog/logging.h>

#include <anvill/Specification.h>

#include "Program.h"

namespace decompile {

ProgramTypeProvider::~ProgramTypeProvider(void) {}

ProgramTypeProvider::ProgramTypeProvider(
    const Program &program_, const ::anvill::TypeTranslator &tt)
    : anvill::TypeProvider(tt),
      program(program_) {}

// Try to return the type of a function starting at address `address`. This
// type is the prototype of the function.
std::optional<anvill::FunctionDecl>
ProgramTypeProvider::TryGetFunctionType(uint64_t address) const {
  const auto decl = program.FindFunction(address);
  if (!decl) {
    return std::nullopt;
  }

  CHECK_NOTNULL(decl->type);
  CHECK_EQ(decl->address, address);

  return *decl;
}

std::optional<anvill::GlobalVarDecl>
ProgramTypeProvider::TryGetVariableType(uint64_t address) const {
  if (auto var_decl = program.FindVariable(address); var_decl) {

    // Check integrity of the var_decl
    CHECK_NOTNULL(var_decl->type);
    CHECK_EQ(var_decl->address, address);
    return *var_decl;

  // if FindVariable fails to get the variable at address; get the variable
  // containing the address
  } else if (auto var_decl = program.FindInVariable(address, data_layout);
             var_decl) {
    CHECK_NOTNULL(var_decl->type);
    CHECK_LE(var_decl->address, address);
    return *var_decl;
  }

  return std::nullopt;
}

}  // namespace decompile
