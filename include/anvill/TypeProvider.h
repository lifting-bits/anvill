/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <llvm/IR/DataLayout.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "Specification.h"
#include "Type.h"

namespace llvm {
class FunctionType;
class LLVMContext;
class Type;
}  // namespace llvm
namespace remill {
class Instruction;
}  // namespace remill
namespace anvill {

// Provides the types of functions, called functions, and accessed data.
class TypeProvider {
 protected:
  llvm::LLVMContext &context;
  llvm::DataLayout data_layout;
  const TypeDictionary type_dictionary;

  explicit TypeProvider(const ::anvill::TypeDictionary &type_dictionary_,
                        const llvm::DataLayout &dl_);

  inline explicit TypeProvider(const TypeTranslator &tt)
      : TypeProvider(tt.Dictionary(), tt.DataLayout()) {}

 public:
  using Ptr = std::shared_ptr<TypeProvider>;

  inline const ::anvill::TypeDictionary &Dictionary(void) const {
    return type_dictionary;
  }

  virtual ~TypeProvider(void);

  // Try to return the type of a function starting at address `address`. This
  // type is the prototype of the function.
  virtual std::optional<FunctionDecl> TryGetFunctionType(
      uint64_t address) const = 0;

  // Try to return the type of a function that has been called from `from_isnt`.
  virtual std::optional<FunctionDecl> TryGetCalledFunctionType(
      const remill::Instruction &from_inst) const;

  // Try to return the type of a function starting at address `to_address`. This
  // type is the prototype of the function. The type can be call site specific,
  // where the call site is `from_inst`.
  virtual std::optional<FunctionDecl> TryGetCalledFunctionType(
      const remill::Instruction &from_inst,
      uint64_t to_address) const;

  // Try to return the variable at given address or containing the address
  virtual std::optional<GlobalVarDecl>
  TryGetVariableType(uint64_t address) const = 0;

  // Try to get the type of the register named `reg_name` on entry to the
  // instruction at `inst_address` inside the function beginning at
  // `func_address`.
  virtual void QueryRegisterStateAtInstruction(
      uint64_t func_address, uint64_t inst_address,
      std::function<void(const std::string &, llvm::Type *,
                         std::optional<uint64_t>)>
          typed_reg_cb) const;

  // Creates a type provider that always fails to provide type information.
  static Ptr CreateNull(const ::anvill::TypeDictionary &type_dictionary_,
                        const llvm::DataLayout &dl_);

 private:
  TypeProvider(const TypeProvider &) = delete;
  TypeProvider(TypeProvider &&) noexcept = delete;
  TypeProvider &operator=(const TypeProvider &) = delete;
  TypeProvider &operator=(TypeProvider &&) noexcept = delete;
  TypeProvider(void) = delete;
};

}  // namespace anvill
