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

#include "FunctionLifter.h"
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

  // Tries to lift the function at `address` and return an `llvm::Function *`.
  llvm::Constant *TryLiftFunction(uint64_t address, llvm::FunctionType *type);

  // Tries to lift the data at `address` and return an `llvm::GlobalAlias *`.
  //
  // A key issue with `TryLiftData` is that we might be requesting `address`,
  // but `address` may be inside of another piece of data, which begins
  // at `data_address`.
  llvm::Constant *TryLiftData(uint64_t address, uint64_t data_address,
                              llvm::Type *data_type);

 private:
  friend class ValueLifter;

  EntityLifterImpl(void) = delete;

  const std::shared_ptr<MemoryProvider> memory_provider;
  const std::shared_ptr<TypeProvider> type_provider;
  const remill::Arch * const arch;

  // Module into which all code is lifted.
  llvm::Module &target_module;

  // Semantics module containing all instruction semantics.
  std::unique_ptr<llvm::Module> semantics_module;

  // Lifts initializers of global variables.
  ValueLifter value_lifter;

  // Used to lift functions.
  FunctionLifter function_lifter;

  std::unordered_map<uint64_t, llvm::Constant *> entities;

  // Work list of functions that need to be optimized.
  std::vector<std::pair<uint64_t, llvm::Constant *>> new_entities;
};

}  // namespace anvill
