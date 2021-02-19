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

#include <anvill/Lifters/EntityLifter.h>

namespace anvill {

// An entity lifter is responsible for lifting functions and data (variables)
// into a target LLVM module.
class EntityLifterImpl {
 public:
  explicit EntityLifter(const std::shared_ptr<const remill::Arch> &arch_,
                        llvm::Module &module_,
                        const MemoryProvider &mem_provider_,
                        const TypeProvider &type_provider_);

  // Tries to lift the entity at `address` and return an `llvm::Function *`
  // or `llvm::GlobalAlias *` relating to that address.
  llvm::Constant *TryLiftEntity(uint64_t address) const;

 private:
  friend class ValueLifter;

  EntityLifterImpl(void) = default;

  std::shared_ptr<EntityLifterImpl> impl;
};

}  // namespace anvill
