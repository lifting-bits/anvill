/*
 * Copyright (c) 2020 Trail of Bits, Inc.
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

#include <anvill/Result.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Type.h>

#include <memory>
#include <optional>
#include <string>
#include <tuple>

namespace llvm {
class DataLayout;
class IntegerType;
class IRBuilderBase;
class LLVMContext;
class StringRef;
class Type;
class Value;
}  // namespace llvm
namespace anvill {

// Parse a type specification into an LLVM type. The following
// grammar captures the syntax of parseable types.
//
//    type: struct_type
//    type: array_type
//    type: vector_type
//    type: function_type
//    type: pointer_type
//    type: integer_type
//    type: float_type
//    type: '?'  // bool.
//    type: 'v'  // void.
//
//    type_list: type type_list
//    type_list: type
//
//    struct_type: '{' type_list '}'              // Anon.
//    struct_type: '=' [0-9]+ '{' type_list '}'   // Def.
//    struct_type: '%' [0-9]+                     // Use.
//
//    array_type: '[' type 'x' [0-9]+ ']'
//    vector_type: '<' type 'x' [0-9]+ '>'
//    function_type: '(' type_list ')'
//    pointer_type: '*' type
//    integer_type: 'b' | 'B' | 'h' | 'H' | 'i' | 'I' | 'l' | 'L' | 'M'
//    float_type: 'f' | 'd' | 'D'
//

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

enum class TypeSign : unsigned char {
  kUnknown,
  kSigned,
  kUnsigned
};

class TypeDictionary {
 public:
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

  // Return the general type of a type, whether or not it is signed, and its
  // size in bits.
  std::tuple<TypeKind, TypeSign, unsigned> Profile(
      llvm::Type *type, const llvm::DataLayout &dl);

  // Returns `true` if `type` is the padding type, or is entirely made up
  // of padding bytes (e.g. an array of the padding type).
  bool IsPadding(llvm::Type *type) const noexcept;

 private:
  TypeDictionary(void) = delete;
};

class TypeSpecifier {
 private:
  std::unique_ptr<TypeSpecifierImpl> impl;

 public:
  ~TypeSpecifier(void);
  TypeSpecifier(llvm::LLVMContext &context, const llvm::DataLayout &dl);

  // Return the type dictionary for this type specifier.
  const TypeDictionary &Dictionary(void) const noexcept;

  // Convert the type `type` to a string encoding. If `alphanum` is `true`
  // then only alphanumeric characters (and underscores) are used. The
  // alphanumeric representation is always safe to use when appended to
  // identifier names.
  std::string EncodeToString(const llvm::Type *type, bool alphanum = false) const;

  // Parse an encoded type string into its represented type.
  Result<llvm::Type *, TypeSpecificationError>
  DecodeFromString(const std::string_view str) const;
};

}  // namespace anvill
