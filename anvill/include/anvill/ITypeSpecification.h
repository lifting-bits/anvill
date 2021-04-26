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
#include <string>

namespace llvm {
class LLVMContext;
class StringRef;
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
    MemoryAllocationFailure,
    InvalidSpecFormat,
    InvalidState,
  };

  std::string spec;
  ErrorCode error_code;
  std::string message;
};

class ITypeSpecification {
 public:
  ITypeSpecification(void) = default;
  virtual ~ITypeSpecification(void) = default;

  using Ptr = std::unique_ptr<ITypeSpecification>;
  static Result<Ptr, TypeSpecificationError>
  Create(llvm::LLVMContext &llvm_context, llvm::StringRef spec);

  static std::string TypeToString(const llvm::Type &type,
                                  const llvm::DataLayout &dl,
                                  bool alphanum = false);

  virtual llvm::Type *Type(void) const = 0;
  virtual bool Sized(void) const = 0;

  virtual const std::string &Spec(void) const = 0;
  virtual const std::string &Description(void) const = 0;

  ITypeSpecification(const ITypeSpecification &) = delete;
  ITypeSpecification &operator=(const ITypeSpecification &) = delete;
};

}  // namespace anvill
