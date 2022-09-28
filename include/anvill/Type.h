/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include "Result.h"

namespace llvm {
class DataLayout;
class IntegerType;
class IRBuilderBase;
class LLVMContext;
class Module;
class StringRef;
class Type;
class Value;
}  // namespace llvm
namespace remill {
class Arch;
}  // namespace remill
namespace anvill {

struct TypeSpecificationError final {
  enum class ErrorCode {
    InvalidSpecFormat,
    InvalidState,
  };

  ErrorCode error_code;
  std::string message;
};

class TypeSpecifierImpl;

enum class TypeKind : unsigned char {
  kUnknown,
  kBoolean,
  kCharacter,
  kIntegral,
  kFloatingPoint,
  kMMX,
  kVoid,
  kPadding
};

enum class TypeSign : unsigned char { kUnknown, kSigned, kUnsigned };

enum class BaseType : int {
  Bool = 0,
  Char = 1,
  SignedChar = 2,
  UnsignedChar = 3,
  Int8 = 4,
  UInt8 = 5,
  Int16 = 6,
  UInt16 = 7,
  Int24 = 8,
  UInt24 = 9,
  Int32 = 10,
  UInt32 = 11,
  Int64 = 12,
  UInt64 = 13,
  Int128 = 14,
  UInt128 = 15,
  Float16 = 16,
  Float32 = 17,
  Float64 = 18,
  Float80 = 19,
  Float96 = 20,
  Float128 = 21,
  MMX64 = 22,
  Void = 23,
  Padding = 24
};

struct PointerType;
struct VectorType;
struct ArrayType;
struct StructType;
struct FunctionType;

struct UnknownType {
  unsigned size;
};

using TypeSpec =
    std::variant<BaseType, std::shared_ptr<PointerType>,
                 std::shared_ptr<VectorType>, std::shared_ptr<ArrayType>,
                 std::shared_ptr<StructType>, std::shared_ptr<FunctionType>,
                 UnknownType>;

struct PointerType {
  TypeSpec pointee;
  bool is_const;
};

struct VectorType {
  TypeSpec base;
  unsigned size;
};

struct ArrayType {
  TypeSpec base;
  unsigned size;
};

struct StructType {
  std::vector<TypeSpec> members;
};

struct FunctionType {
  TypeSpec return_type;
  std::vector<TypeSpec> arguments;
  bool is_variadic;
};

// Dictionary of types to be used by the type specifier.
class TypeDictionary {
 public:
  TypeDictionary(const TypeDictionary &) = default;

  // Initialize a type dictionary for an LLVM context.
  //
  // NOTE(pag): Technically, if a user wants to use their own custom types
  //            with the type specifier, then they need only mutate the type
  //            dictionary named types after initialization, then pass the
  //            instance to the `TypeSpecifier`.
  explicit TypeDictionary(llvm::LLVMContext &context_);

  union {
    struct NamedTypes {
      llvm::Type *bool_;  // `?`.
      llvm::Type *char_;  // `c`.
      llvm::Type *schar;  // `s`.
      llvm::Type *uchar;  // `S`.
      llvm::Type *int8;  // `b`.
      llvm::Type *uint8;  // `B`.
      llvm::Type *int16;  // `h`.
      llvm::Type *uint16;  // `H`.
      llvm::Type *int24;  // `w`.
      llvm::Type *uint24;  // `W`.
      llvm::Type *int32;  // `i`.
      llvm::Type *uint32;  // `I`.
      llvm::Type *int64;  // `l`.
      llvm::Type *uint64;  // `L`.
      llvm::Type *int128;  // `o`.
      llvm::Type *uint128;  // `O`.
      llvm::Type *float16;  // `e`.
      llvm::Type *float32;  // `f`.
      llvm::Type *float64;  // `F`.
      llvm::Type *float80_12;  // `d`.
      llvm::Type *float80_16;  // `D`.
      llvm::Type *float128;  // `Q`.
      llvm::Type *m64;  // `M`.
      llvm::Type *void_;  // `v`.
      llvm::Type *padding;  // `p`.
    } named;
    llvm::Type *indexed[sizeof(NamedTypes) / sizeof(llvm::Type *)];
  } u;

  // Convert a value to a specific type.
  llvm::Value *ConvertValueToType(llvm::IRBuilderBase &, llvm::Value *,
                                  llvm::Type *) const;

  // Returns `true` if `type` is the padding type, or is entirely made up
  // of padding bytes (e.g. an array of the padding type).
  bool IsPadding(llvm::Type *type) const noexcept;

 private:
  TypeDictionary(void) = delete;
};

enum EncodingFormat : bool {
  kDefault = false,
  kValidSymbolCharsOnly = true
};

// Translates between two type formats:
//
//    1)  A textual format, that is relatively compact and explicit. This format
//        itself has two possible encodings:
//
//        1.a)  The default encoding, which includes characters like `*`, `[`,
//              etc.
//
//        1.b)  The "valid symbol characters only" encoding, which uses only
//              characters in the alphabet a-z, A-Z, 0-9, and _.
//
//    2)  The LLVM internal type representation.
//
//        TODO(pag): Conversions to LLVM types do not do any kind of fancy
//                   de-duplication. Make them do this.
class TypeTranslator {
 private:
  std::unique_ptr<TypeSpecifierImpl> impl;

 public:
  ~TypeTranslator(void);

  // Initialize a type specifier with a type dictionary.
  TypeTranslator(const TypeDictionary &type_dict, const llvm::DataLayout &dl);
  TypeTranslator(const TypeDictionary &type_dict, const llvm::Module &module);
  TypeTranslator(const TypeDictionary &type_dict, const remill::Arch *arch);
  TypeTranslator(const TypeDictionary &type_dict,
                 const std::unique_ptr<const remill::Arch> &arch);

  // Return the type dictionary for this type specifier.
  const TypeDictionary &Dictionary(void) const noexcept;

  // Return a reference to the data layout used by this type translator.
  const llvm::DataLayout &DataLayout(void) const noexcept;

  // Convert the type `type` to a string encoding. If `alphanum` is `true`
  // then only alphanumeric characters (and underscores) are used. The
  // alphanumeric representation is always safe to use when appended to
  // identifier names.
  //
  // See `docs/TypeEncoding.md` for information on how different types are
  // represented.
  std::string EncodeToString(
      llvm::Type *type,
      EncodingFormat alphanum = EncodingFormat::kDefault) const;

  Result<llvm::Type *, TypeSpecificationError>
  DecodeFromSpec(TypeSpec spec) const;
};

}  // namespace anvill
