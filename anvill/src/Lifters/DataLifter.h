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

#include <anvill/Lifters/DataLifter.h>

#include <cstdint>
#include <memory>
#include <map>
#include <set>
#include <unordered_map>
#include <anvill/Decl.h>

#include <anvill/Lifters/Options.h>

namespace llvm {
class GlobalAlias;
class LLVMContext;
class Module;
class Type;
class Value;
}  // namespace llvm
namespace anvill {

class LifterOptions;
class MemoryProvider;
class TypeProvider;

// Orchestrates lifting of instructions and control-flow between instructions.
class DataLifterImpl {
 public:
  ~DataLifterImpl(void);

  DataLifterImpl(const LifterOptions &options_,
                 MemoryProvider &memory_provider_,
                 TypeProvider &type_provider_);

  // Declare a lifted a variable. Will return `nullptr` if the memory is
  // not accessible.
  llvm::GlobalValue *DeclareData(const GlobalVarDecl &decl,
                                 ContextImpl &lifter_context);

  // Lift a function. Will return `nullptr` if the memory is not accessible.
  llvm::GlobalValue *LiftData(const GlobalVarDecl &decl,
                              ContextImpl &lifter_context);

  // Returns the address of a named function.
  std::optional<uint64_t> AddressOfNamedData(
      const std::string &data_name) const;

 private:
  friend class FunctionLifter;

  // Declare a lifted a variable. Will not return `nullptr`.
  llvm::GlobalValue *GetOrDeclareData(const GlobalVarDecl &decl,
                                      ContextImpl &lifter_context);

  const LifterOptions options;
  MemoryProvider &memory_provider;
  TypeProvider &type_provider;

  // Context associated with `module`.
  llvm::LLVMContext &context;
};

}  // namespace anvill
