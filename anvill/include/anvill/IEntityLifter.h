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
#include <optional>

#include <anvill/ILifterOptions.h>

namespace anvill {

// Lifting context for anvill. The lifting context keeps track of the options
// used for lifting, the module into which lifted objects are placed, and
// a the mapping between lifted objects and their original addresses in the
// binary.
class IEntityLifter {
 public:
  IEntityLifter(void) = default;
  virtual ~IEntityLifter(void) = default;

  using Ptr = std::unique_ptr<IEntityLifter>;
  static Ptr Create(LifterOptions::Ptr options);

  // Return the options being used by this entity lifter.
  virtual const LifterOptions &Options(void) const = 0;

  // Lift a function and return it. Returns `nullptr` if there was a failure.
  virtual llvm::Function *LiftEntity(const FunctionDecl &decl) const = 0;

  // Lift a variable and return it. Returns `nullptr` if there was a failure.
  virtual llvm::Constant *LiftEntity(const GlobalVarDecl &decl) const = 0;

  // Lift a function and return it. Returns `nullptr` if there was a failure.
  virtual llvm::Function *DeclareEntity(const FunctionDecl &decl) const = 0;

  // Lift a variable and return it. Returns `nullptr` if there was a failure.
  virtual llvm::Constant *DeclareEntity(const GlobalVarDecl &decl) const = 0;

  IEntityLifter(const IEntityLifter &) = delete;
  IEntityLifter(IEntityLifter &&) noexcept = delete;

  IEntityLifter &operator=(const IEntityLifter &) = delete;
  IEntityLifter &operator=(IEntityLifter &&) noexcept = delete;
};

}  // namespace anvill
