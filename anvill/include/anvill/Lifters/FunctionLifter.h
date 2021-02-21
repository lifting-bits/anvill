/*
 * Copyright (c) 2021 Trail of Bits, Inc.
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

#include <cstdint>
#include <memory>

#include <anvill/Lifters/Options.h>

namespace llvm {
class Function;
}  // namespace llvm
namespace anvill {

struct FunctionDecl;
class MemoryProvider;
class TypeProvider;

class FunctionLifterImpl;

// Orchestrates lifting of instructions and control-flow between instructions.
class FunctionLifter {
 public:
  ~FunctionLifter(void);

  explicit FunctionLifter(const LifterOptions &options_,
                          MemoryProvider &memory_provider_,
                          TypeProvider &type_provider_);

  // Lifts the machine code function starting at address `address`, and using
  // `options_.arch` as the architecture for lifting, into `options_.module`.
  // Returns an `llvm::Function *` that is part of `options_.module`.
  llvm::Function *LiftFunction(const FunctionDecl &decl) const;

  FunctionLifter(const FunctionLifter &) = default;
  FunctionLifter(FunctionLifter &&) noexcept = default;
  FunctionLifter &operator=(const FunctionLifter &) = default;
  FunctionLifter &operator=(FunctionLifter &&) noexcept = default;

 private:
  FunctionLifter(void) = delete;

  std::shared_ptr<FunctionLifterImpl> impl;
};

}  // namespace anvill
