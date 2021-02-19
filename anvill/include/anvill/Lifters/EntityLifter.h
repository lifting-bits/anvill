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
class Constant;
class Module;
}  // namespace llvm
namespace remill {
class Arch;
}  // namespace remill
namespace anvill {

class EntityLifterImpl;
class ValueLifter;
class MemoryProvider;
class TypeProvider;

// An entity lifter is responsible for lifting functions and data (variables)
// into a target LLVM module.
class EntityLifter {
 public:
  ~EntityLifter(void);

  explicit EntityLifter(const std::shared_ptr<MemoryProvider> &mem_provider_,
                        const std::shared_ptr<TypeProvider> &type_provider_,
                        const remill::Arch *arch_, llvm::Module &module_);

  // Tries to lift the entity at `address` and return an `llvm::Function *`
  // or `llvm::GlobalAlias *` relating to that address.
  llvm::Constant *TryLiftEntity(uint64_t address) const;

 private:
  friend class ValueLifter;

  EntityLifter(void) = default;

  std::shared_ptr<EntityLifterImpl> impl;
};

}  // namespace anvill
