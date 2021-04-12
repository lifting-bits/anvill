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

// A value, such as a parameter or a return value. Values are resident
// in one of two locations: either in a register, represented by a non-
// nullptr `reg` value, or in memory, at `[mem_reg + mem_offset]`.
//
// In the case of `mem_reg` being used by a parameter or return value,
// we interpret this as meaning: this value is resident in the memory
// address `mem_reg + mem_offset`, using the *initial value* of
// `mem_reg` on entry to the function.
//
// The memory resident value location exists to represent stack-passed
// values. In the case where return-value optimization is implemented
// (in the ABI) as writing into the caller's stack frame, then this
// mechanism can work. However, often times, RVO is implemented by having
// the caller allocate the space, and pass a pointer to that space into
// the callee, and so that should be represented using a parameter.
struct ValueDecl {
  const remill::Register *reg{nullptr};
  const remill::Register *mem_reg{nullptr};
  int64_t mem_offset{0};

  // Type of this value.
  llvm::Type *type{nullptr};

  llvm::json::Object SerializeToJSON(const llvm::DataLayout &dl) const;
};

}  // namespace anvill
