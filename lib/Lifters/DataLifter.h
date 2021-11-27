/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <anvill/Type.h>

#include <cstdint>
#include <memory>

namespace llvm {
class Constant;
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

struct GlobalVarDecl;

// Orchestrates lifting of instructions and control-flow between instructions.
class DataLifter {
 public:
  ~DataLifter(void);

  DataLifter(const LifterOptions &options_);

  // Lift a function. Will return `nullptr` if the memory is not accessible.
  llvm::Constant *LiftData(const GlobalVarDecl &decl,
                           EntityLifterImpl &lifter_context);

  // Declare a lifted a variable. Will not return `nullptr`.
  llvm::Constant *GetOrDeclareData(const GlobalVarDecl &decl,
                                   EntityLifterImpl &lifter_context);

 private:
  friend class FunctionLifter;

  const LifterOptions &options;
  const MemoryProvider &memory_provider;
  const TypeProvider &type_provider;
  const TypeTranslator type_specifier;

  // Context associated with `module`.
  llvm::LLVMContext &context;
};

}  // namespace anvill
