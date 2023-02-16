/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <anvill/Declarations.h>
#include <anvill/Result.h>

#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <unordered_map>

#include "anvill/Type.h"
#include "specification.pb.h"

namespace llvm {
class LLVMContext;
class Type;
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
struct VariableDecl;
struct ParameterDecl;
struct ValueDecl;

class ProtobufTranslator {
 private:
  const remill::Arch *const arch;

  // Type translator, which can encode/decode types.
  const anvill::TypeTranslator &type_translator;

  // Context associated with the architecture.
  llvm::LLVMContext &context;

  // Two different void type interpretations. May be the same.
  llvm::Type *const void_type;
  llvm::Type *const dict_void_type;

  std::unordered_map<std::int64_t, TypeSpec> &type_map;

  anvill::Result<TypeSpec, std::string>
  DecodeType(const ::specification::TypeSpec &obj) const;

  anvill::Result<TypeSpec, std::string> DecodeType(
      const ::specification::TypeSpec &obj,
      const std::unordered_map<std::int64_t, ::specification::TypeSpec> &map);

  // Parse the location of a value. This applies to both parameters and
  // return values.
  anvill::Result<ValueDecl, std::string>
  DecodeValue(const ::specification::Value &obj, TypeSpec type,
              const char *desc) const;


  Result<std::monostate, std::string>
  ParseIntoCallableDecl(const ::specification::Callable &obj,
                        std::optional<uint64_t> address,
                        CallableDecl &decl) const;

  void ParseCFGIntoFunction(const ::specification::Function &obj,
                            FunctionDecl &decl) const;

  void AddLiveValuesToBB(
      std::unordered_map<uint64_t, std::vector<HighSymbolDecl>> &map,
      uint64_t bb_addr,
      const ::google::protobuf::RepeatedPtrField<::specification::HighSymbol>
          &values) const;


 public:
  explicit ProtobufTranslator(
      const anvill::TypeTranslator &type_translator_, const remill::Arch *arch_,
      std::unordered_map<std::int64_t, TypeSpec> &type_map);

  inline explicit ProtobufTranslator(
      const anvill::TypeTranslator &type_translator_,
      const std::unique_ptr<const remill::Arch> &arch_,
      std::unordered_map<std::int64_t, TypeSpec> &type_map)
      : ProtobufTranslator(type_translator_, arch_.get(), type_map) {}

  // Parse a parameter from the Protobuf spec. Parameters should have names,
  // as that makes the bitcode slightly easier to read, but names are
  // not required. They must have types, and these types should be mostly
  // reflective of what you would see if you compiled C/C++ source code to
  // LLVM bitcode, and inspected the type of the corresponding parameter in
  // the bitcode.
  Result<ParameterDecl, std::string>
  DecodeParameter(const ::specification::Parameter &obj) const;

  // Try to decode function info from a Protobuf specification. These
  // are really function prototypes / declarations, and not any instruction
  // data (that is separate, if present).
  Result<FunctionDecl, std::string>
  DecodeFunction(const ::specification::Function &obj) const;

  Result<CallSiteDecl, std::string>
  DecodeCallsite(const ::specification::Callsite &cs) const;

  // Try to decode global variable information from a Protobuf specification. These
  // are really variable prototypes / declarations.
  Result<VariableDecl, std::string>
  DecodeGlobalVar(const ::specification::GlobalVariable &obj) const;

  Result<CallableDecl, std::string>
  DecodeDefaultCallableDecl(const ::specification::Function &obj) const;

  Result<std::monostate, std::string>
  DecodeTypeMap(const ::google::protobuf::Map<std::int64_t,
                                              ::specification::TypeSpec> &map);
};

}  // namespace anvill
