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

namespace llvm {
class GlobalValue;
}  // namespace llvm
namespace anvill {

class Context;
class ContextImpl;
struct GlobalVarDecl;

// Manages global variables, lifting their initializers, and presenting aliases
// into the global variables. The key challenge with the data lifter is that
// some global variables may overlap or be adjacent. When this happens, it might
// decide to merge things behind the scenes. This is transparent to users of
// the data lifter, which only see things in terms of `GlobalAlias`es to what
// they ask for.
class DataLifter {
 public:
  ~DataLifter(void);

  explicit DataLifter(const Context &lifter_context);

  // Lifts the raw bytes at address `decl.address`, and using
  //
  // NOTE(pag): If this function returns `nullptr` then it means that we cannot
  //            lift the function (e.g. bad address, or non-executable memory).
  llvm::GlobalValue *LiftData(const GlobalVarDecl &decl) const;

  // Declare the function associated with `decl` in the context's module.
  llvm::GlobalValue *DeclareData(const GlobalVarDecl &decl) const;

  DataLifter(const DataLifter &) = default;
  DataLifter(DataLifter &&) noexcept = default;
  DataLifter &operator=(const DataLifter &) = default;
  DataLifter &operator=(DataLifter &&) noexcept = default;

 private:
  DataLifter(void) = delete;

  std::shared_ptr<ContextImpl> impl;
};

}  // namespace anvill
