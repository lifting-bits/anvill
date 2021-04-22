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

#include <anvill/ITypeSpecification.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Type.h>
#include <llvm/Support/Error.h>
#include <remill/BC/Compat/Error.h>
#include <remill/BC/Compat/VectorType.h>

#include <sstream>
#include <vector>

namespace anvill {

class TypeSpecification final : public ITypeSpecification {
 public:
  virtual ~TypeSpecification(void) override;

  virtual llvm::Type *Type(void) const override;
  virtual bool Sized(void) const override;

  virtual const std::string &Spec(void) const override;
  virtual const std::string &Description(void) const override;

 private:
  struct Context final {
    llvm::Type *type{nullptr};
    bool sized{false};
    std::string spec;
    std::string description;
  };

  Context context;

  TypeSpecification(llvm::LLVMContext &llvm_context, llvm::StringRef spec);

  friend class ITypeSpecification;

 public:
  // Parse some characters out of `spec` starting at index `i`, where
  // the characters are accepted by the predicate `filter`, and store
  // the result in `*out`.
  template <typename Filter, typename T>
  static bool Parse(llvm::StringRef spec, size_t &i, Filter filter, T *out);

  static TypeSpecificationError
  CreateError(const std::string &spec,
              TypeSpecificationError::ErrorCode error_code,
              const std::string &message = std::string());

  // Parse a type specification into an LLVM type. See TypeParser.h
  // for the grammar that generates the language which `ParseType`
  // accepts.
  static Result<llvm::Type *, TypeSpecificationError>
  ParseType(llvm::LLVMContext &llvm_context, std::vector<llvm::Type *> &ids,
            llvm::SmallPtrSetImpl<llvm::Type *> &size_checked,
            llvm::StringRef spec, size_t &i);


  static Result<Context, TypeSpecificationError>
  ParseSpec(llvm::LLVMContext &llvm_context, llvm::StringRef spec);
};

template <typename Filter, typename T>
bool TypeSpecification::Parse(llvm::StringRef spec, size_t &i, Filter filter,
                              T *out) {
  std::stringstream ss;

  auto found = false;
  for (; i < spec.size(); ++i) {
    if (filter(spec[i])) {
      ss << spec[i];
      found = true;

    } else {
      break;
    }
  }

  if (!found) {
    return false;
  }

  ss >> *out;
  return !ss.bad();
}

}  // namespace anvill
