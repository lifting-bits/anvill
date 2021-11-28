/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "JSON.h"
#include "Result.h"

namespace llvm {
class BasicBlock;
class DataLayout;
class Function;
class FunctionType;
class GlobalVariable;
class LLVMContext;
class Module;
class Type;
class Value;
namespace CallingConv {
using ID = unsigned;
}  // namespace CallingConv
namespace json {
class Object;
class Value;
}  // namespace json
}  // namespace llvm
namespace remill {
class Arch;
class IntrinsicTable;
struct Register;
}  // namespace remill
namespace anvill {

class EntityLifter;
class SpecificationControlFlowProvider;
class SpecificationImpl;
class SpecificationMemoryProvider;
class SpecificationTypeProvider;
class TypeDictionary;
class TypeTranslator;

// Represents the data pulled out of a JSON (sub-)program specification.
class Specification {
 private:
  friend class SpecificationControlFlowProvider;
  friend class SpecificationMemoryProvider;
  friend class SpecificationTypeProvider;

  Specification(void) = delete;

  std::shared_ptr<SpecificationImpl> impl;

  explicit Specification(std::shared_ptr<SpecificationImpl> impl_);

 public:
  ~Specification(void);

  // Return the architecture used by this specification.
  std::shared_ptr<const remill::Arch> Arch(void) const;

  // Return the type dictionary used by this specification.
  const ::anvill::TypeDictionary &TypeDictionary(void) const;

  // Return the type translator used by this specification.
  const ::anvill::TypeTranslator &TypeTranslator(void) const;

  // Try to create a program from a JSON specification. Returns a string error
  // if something went wrong.
  static anvill::Result<Specification, JSONDecodeError> DecodeFromJSON(
      llvm::LLVMContext &context, const llvm::json::Value &val);

  // Try to encode the specification into JSON.
  anvill::Result<llvm::json::Object, JSONEncodeError> EncodeToJSON(void);

  // Return the function beginning at `address`, or an empty `shared_ptr`.
  std::shared_ptr<const FunctionDecl> FunctionAt(std::uint64_t address) const;

  // Return the global variable beginning at `address`, or an empty `shared_ptr`.
  std::shared_ptr<const GlobalVarDecl> GlobalVarAt(std::uint64_t address) const;

  // Return the global variable containing `address`, or an empty `shared_ptr`.
  std::shared_ptr<const GlobalVarDecl> GlobalVarContaining(
      std::uint64_t address) const;

  // Lift all functions.
  void LiftAllFunctions(EntityLifter &lifter) const;

  // Lift all variables.
  void LiftAllVariables(EntityLifter &lifter) const;
};

}  // namespace anvill
