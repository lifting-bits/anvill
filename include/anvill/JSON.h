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
}  // namespace json
}  // namespace llvm
namespace remill {
class Arch;
}  // namespace remill
namespace anvill {

class Specification;
class SpecificationImpl;
class TypeTranslator;

struct CallSiteDecl;
struct FunctionDecl;
struct GlobalVarDecl;
struct ParameterDecl;
struct ValueDecl;

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
  anvill::Result<ValueDecl, JSONDecodeError>
  DecodeValue(const llvm::json::Object *obj, const char *desc,
              bool allow_void=false) const;

 public:
  explicit JSONTranslator(const anvill::TypeTranslator &type_translator_,
                          const remill::Arch *arch_);

  inline explicit JSONTranslator(
      const anvill::TypeTranslator &type_translator_,
      const std::unique_ptr<const remill::Arch> &arch_)
      : JSONTranslator(type_translator_, arch_.get()) {}

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

  // Try to decode function info from a JSON specification. These
  // are really function prototypes / declarations, and not any instruction
  // data (that is separate, if present).
  Result<FunctionDecl, JSONDecodeError>
  DecodeFunction(const llvm::json::Object *obj) const;

  // Try to decode call site information from a JSON specification. This is a
  // lot like function declarations, but is specific to a call site, rather
  // than specific to the function's entrypoint.
  Result<CallSiteDecl, JSONDecodeError>
  DecodeCallSite(const llvm::json::Object *obj) const;

  // Try to decode global variable information from a JSON specification. These
  // are really variable prototypes / declarations.
  Result<GlobalVarDecl, JSONDecodeError>
  DecodeGlobalVar(const llvm::json::Object *obj) const;

  // Encode a function declaration.
  Result<llvm::json::Object, JSONEncodeError>
  Encode(const FunctionDecl &decl) const;

  // Encode a call site declaration.
  Result<llvm::json::Object, JSONEncodeError>
  Encode(const CallSiteDecl &decl) const;

  // Encode a variable declaration.
  Result<llvm::json::Object, JSONEncodeError>
  Encode(const GlobalVarDecl &decl) const;
};

}  // namespace anvill
