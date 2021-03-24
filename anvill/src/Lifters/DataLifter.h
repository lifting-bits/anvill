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

#include <anvill/Decl.h>
#include <anvill/Lifters/Options.h>

#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <unordered_map>

namespace llvm {
class GlobalAlias;
class LLVMContext;
class Module;
class Type;
class Value;
}  // namespace llvm
namespace anvill {

class EntityLifterImpl;
class LifterOptions;
class MemoryProvider;
class TypeProvider;

// Orchestrates lifting of instructions and control-flow between instructions.
class DataLifter {
 public:
  ~DataLifter(void);

  DataLifter(const LifterOptions &options_, MemoryProvider &memory_provider_,
             TypeProvider &type_provider_);

  // Lift a function. Will return `nullptr` if the memory is not accessible.
  llvm::Constant *LiftData(const GlobalVarDecl &decl,
                           EntityLifterImpl &lifter_context);

  // Declare a lifted a variable. Will not return `nullptr`.
  llvm::Constant *GetOrDeclareData(const GlobalVarDecl &decl,
                                   EntityLifterImpl &lifter_context);

 private:
  friend class FunctionLifter;

  const LifterOptions options;
  MemoryProvider &memory_provider;
  TypeProvider &type_provider;

  // Context associated with `module`.
  llvm::LLVMContext &context;
};

}  // namespace anvill
