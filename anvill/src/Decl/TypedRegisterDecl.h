/*
 * Copyright (c) 2020 Trail of Bits, Inc.
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

#include <llvm/IR/CallingConv.h>

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <llvm/Support/JSON.h>

#include <remill/Arch/Arch.h>
#include <remill/BC/Compat/Error.h>

namespace anvill {

// A TypedRegisterDecl stores inferred types and values for a given register
// Inferred infromation can come from binja, ida, or some other tool
struct TypedRegisterDecl {
  const remill::Register *reg;
  llvm::Type *type;
  std::optional<uint64_t> value;
};

}  // namespace anvill
