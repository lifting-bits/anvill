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

#include <anvill/Lifters/Context.h>
#include <anvill/Lifters/Options.h>
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

class ValueLifterImpl;

// An entity lifter is responsible for lifting functions and data (variables)
// into a target LLVM module.
class ContextImpl {
 public:
  ~ContextImpl(void);

  explicit ContextImpl(
      const LifterOptions &options_,
      const std::shared_ptr<MemoryProvider> &mem_provider_,
      const std::shared_ptr<TypeProvider> &type_provider_);

  // Tries to lift the data at `address` and return an `llvm::GlobalAlias *`.
  //
  // A key issue with `TryLiftData` is that we might be requesting `address`,
  // but `address` may be inside of another piece of data, which begins
  // at `data_address`.
  llvm::Constant *TryLiftData(uint64_t address, uint64_t data_address,
                              llvm::Type *data_type);

  // Tells the entity lifter that `func` is the lifted function at `address`.
  // There is some collusion between the `EntityLifter` and the `FunctionLifter`
  // to ensure their view of the world remains consistent.
  void SetLiftedFunction(uint64_t address, llvm::Function *func);

  llvm::Function *GetLiftedFunction(uint64_t address) const;

 private:
  friend class Context;
  friend class FunctionLifter;
  friend class ValueLifter;

  ContextImpl(void) = delete;

  // Options used to guide how lifting should occur.
  const LifterOptions options;

  // Provider of memory when asking for bytes for instructions or data.
  const std::shared_ptr<MemoryProvider> memory_provider;

  // Provider of type information when asking for function prototypes.
  const std::shared_ptr<TypeProvider> type_provider;

  // Lifts initializers of global variables.
  //
  // TODO(pag): This is a bit dumb, but there's a circular dependency here :-/
  ValueLifterImpl value_lifter;

  // Used to lift functions.
  FunctionLifterImpl function_lifter;

  // Maps native code addresses to lifted entities. The lifted entities reside
  // in the `options.module` module.
  std::unordered_map<uint64_t, llvm::GlobalValue *> address_to_entity;

  // Maps lifted entities to native addresses. The lifted
  std::unordered_map<llvm::GlobalValue *, uint64_t> entity_to_address;
};

}  // namespace anvill
