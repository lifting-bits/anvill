/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <type_traits>

#include "Result.h"

namespace llvm {
class LLVMContext;
class Type;
namespace json {
class Object;
class Value;
}  // namespace json
}  // namespace llvm
namespace remill {
class Arch;
}  // namespace remill
namespace anvill {

class FunctionDecl;
class ParameterDecl;
class TypeTranslator;
class ValueDecl;

class JSONDecodeError {
 public:
  inline JSONDecodeError(std::string message_,
                         const llvm::json::Object *object_=nullptr)
      : message(std::move(message_)),
        object(object_) {}

  const std::string message;
  const llvm::json::Object * const object;
};

class JSONEncodeError {
 public:
  inline JSONEncodeError(std::string message_, const ValueDecl *decl_=nullptr)
      : message(std::move(message_)),
        decl(decl_) {}

  const std::string message;
  const ValueDecl * const decl;
};

// Parse JSON specifications into declarations.
class JSONTranslator {
 private:
  const remill::Arch * const arch;

  // Type translator, which can encode/decode types.
  const anvill::TypeTranslator &type_translator;

  // Context associated with the architecture.
  llvm::LLVMContext &context;

  // Two different void type interpretations. May be the same.
  llvm::Type * const void_type;
  llvm::Type * const dict_void_type;

  // Parse the location of a value. This applies to both parameters and
  // return values.
  anvill::Result<anvill::ValueDecl, JSONDecodeError>
  DecodeValue(const llvm::json::Object *obj, const char *desc) const;

 public:
  explicit JSONTranslator(const remill::Arch *arch_,
                          const anvill::TypeTranslator &type_translator_);

  // Parse a parameter from the JSON spec. Parameters should have names,
  // as that makes the bitcode slightly easier to read, but names are
  // not required. They must have types, and these types should be mostly
  // reflective of what you would see if you compiled C/C++ source code to
  // LLVM bitcode, and inspected the type of the corresponding parameter in
  // the bitcode.
  Result<ParameterDecl, JSONDecodeError>
  DecodeParameter(const llvm::json::Object *obj) const;

  // Parse a return value from the JSON spec.
  Result<ValueDecl, JSONDecodeError>
  DecodeReturnValue(const llvm::json::Object *obj) const;

  // Try to unserialize function info from a JSON specification. These
  // are really function prototypes / declarations, and not any isntruction
  // data (that is separate, if present).
  Result<FunctionDecl, JSONDecodeError>
  DecodeFunction(const llvm::json::Object *obj) const;

  // Variants of the above, but operating on strings.

  Result<ParameterDecl, JSONDecodeError>
  DecodeParameter(std::string_view data) const;

  Result<ValueDecl, JSONDecodeError>
  DecodeReturnValue(std::string_view data) const;

  Result<FunctionDecl, JSONDecodeError>
  DecodeFunction(std::string_view data) const;

  // Encode a function declaration.
  Result<llvm::json::Object, JSONEncodeError>
  Encode(const FunctionDecl &decl) const;
};

}  // namespace anvill
