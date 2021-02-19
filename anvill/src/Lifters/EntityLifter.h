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
#include <anvill/Providers/MemoryProvider.h>
#include <anvill/Providers/TypeProvider.h>

#include <unordered_map>
#include <utility>
#include <vector>

#include "ValueLifter.h"

namespace llvm {
class GlobalAlias;
class Function;
}  // namespace llvm
namespace anvill {

// An entity lifter is responsible for lifting functions and data (variables)
// into a target LLVM module.
class EntityLifterImpl {
 public:
  ~EntityLifterImpl(void);

  explicit EntityLifterImpl(
      const std::shared_ptr<MemoryProvider> &mem_provider_,
      const std::shared_ptr<TypeProvider> &type_provider_,
      const remill::Arch *arch_, llvm::Module &module_);

  // Tries to lift the entity at `address` and return an `llvm::Function *`
  // or `llvm::GlobalAlias *` relating to that address.
  llvm::Constant *TryLiftEntity(uint64_t address) const;

 private:
  friend class ValueLifter;

  EntityLifterImpl(void) = delete;

  const std::shared_ptr<MemoryProvider> mem_provider;
  const std::shared_ptr<TypeProvider> type_provider;
  const remill::Arch * const arch;

  // Module into which all code is lifted.
  llvm::Module &module;

  // Semantics module containing all instruction semantics.
  std::unique_ptr<llvm::Module> semantics_module;

  // Lifts initializers of global variables.
  ValueLifter value_lifter;

  std::unordered_map<uint64_t, llvm::Constant *> entities;

  // Work list of functions that need to be lifted.
  std::vector<std::pair<uint64_t, llvm::Function *>> functions_to_lift;

  // Work list of data variables that need to be lifted.
  std::vector<std::pair<uint64_t, llvm::GlobalAlias *>> data_to_lift;
};

}  // namespace anvill
