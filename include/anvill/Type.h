/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <remill/Arch/ArchGroup.h>

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>

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

  // Return the general type of a type, whether or not it is signed, and its
  // size in bits.
  std::tuple<TypeKind, TypeSign, unsigned> Profile(llvm::Type *type,
                                                   const llvm::DataLayout &dl);

  // Returns `true` if `type` is the padding type, or is entirely made up
  // of padding bytes (e.g. an array of the padding type).
  bool IsPadding(llvm::Type *type) const noexcept;

 private:
  TypeDictionary(void) = delete;
};

enum EncodingFormat : bool { kDefault = false, kValidSymbolCharsOnly = true };

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
  TypeTranslator(const TypeDictionary &type_dict,
                 const remill::MachineSemantics &arch);

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
  std::string
  EncodeToString(llvm::Type *type,
                 EncodingFormat alphanum = EncodingFormat::kDefault) const;

  // Parse an encoded type string into its represented type.
  //
  // See `docs/TypeEncoding.md` for information on how different types are
  // represented.
  Result<llvm::Type *, TypeSpecificationError>
  DecodeFromString(const std::string_view str) const;
};

}  // namespace anvill
