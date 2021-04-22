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

#include "TypeSpecification.h"

#include <remill/BC/Util.h>

namespace anvill {

TypeSpecification::~TypeSpecification(void) {}

llvm::Type *TypeSpecification::Type(void) const {
  return context.type;
}

bool TypeSpecification::Sized(void) const {
  return context.sized;
}

const std::string &TypeSpecification::Spec(void) const {
  return context.spec;
}

const std::string &TypeSpecification::Description(void) const {
  return context.description;
}

TypeSpecification::TypeSpecification(llvm::LLVMContext &llvm_context,
                                     llvm::StringRef spec) {
  auto context_res = ParseSpec(llvm_context, spec);
  if (!context_res.Succeeded()) {
    throw context_res.TakeError();
  }

  context = context_res.TakeValue();
}

TypeSpecificationError
TypeSpecification::CreateError(const std::string &spec,
                               TypeSpecificationError::ErrorCode error_code,
                               const std::string &message) {

  TypeSpecificationError error;
  error.spec = spec;
  error.error_code = error_code;
  error.message = message;

  return error;
}

Result<llvm::Type *, TypeSpecificationError>
TypeSpecification::ParseType(llvm::LLVMContext &llvm_context,
                             std::vector<llvm::Type *> &ids,
                             llvm::SmallPtrSetImpl<llvm::Type *> &size_checked,
                             llvm::StringRef spec, size_t &i) {

  llvm::StructType *struct_type = nullptr;

  while (i < spec.size()) {
    auto ch = spec[i];
    bool in_retry = false;
  retry:
    switch (ch) {

      // An underscore is a prefix to re-interpret the subsequent letter/digit
      // as a different character. This lets us have a type encoding that is
      // purely alphanumeric, and thus well-suited toward embedding in symbol
      // names.
      case '_':
        if ((i + 1) >= spec.size()) {
          return CreateError(
              spec.str(), TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Unterminated continuation character '_' at end of type specification");

        } else if (in_retry) {
          return CreateError(
              spec.str(), TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Cannot have continuation '_' following a continuation '_' in type specification");

        } else {
          in_retry = true;
          switch (spec[++i]) {

            // `_M` -> `%`.
            case 'M': ch = '%'; goto retry;

            // `_S` -> `*`.
            case 'S': ch = '*'; goto retry;

            // `_A` -> `(`.
            case 'A': ch = '('; goto retry;

            // `_B` -> `)`.
            case 'B': ch = ')'; goto retry;

            // `_C` -> `[`.
            case 'C': ch = '['; goto retry;

            // `_D` -> `]`.
            case 'D': ch = ']'; goto retry;

            // `_E` -> `{`.
            case 'E': ch = '['; goto retry;

            // `_F` -> `}`.
            case 'F': ch = ']'; goto retry;

            // `_G` -> `<`.
            case 'G': ch = '<'; goto retry;

            // `_H` -> `>`.
            case 'H': ch = '>'; goto retry;

            // `_V` -> `&`.
            case 'V': ch = '&'; goto retry;
          }
        }

      // Parse a structure type.
      case '{': {
        llvm::SmallVector<llvm::Type *, 4> elem_types;
        for (i += 1; i < spec.size() && spec[i] != '}';) {
          auto maybe_elem_type =
              ParseType(llvm_context, ids, size_checked, spec, i);
          if (!maybe_elem_type.Succeeded()) {
            return maybe_elem_type.TakeError();
          }

          if (auto elem_type = maybe_elem_type.Value()) {
            if (!elem_type->isSized(&size_checked)) {
              return CreateError(
                  spec.str(),
                  TypeSpecificationError::ErrorCode::InvalidSpecFormat,
                  "Cannot create structure with an unsized element type (e.g. void or function type) in type specification");
            }

            elem_types.push_back(elem_type);
          } else {
            break;
          }
        }

        if (elem_types.empty()) {
          return CreateError(
              spec.str(), TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Invalid structure in type specification");
        }

        if (i >= spec.size() || '}' != spec[i]) {
          return CreateError(
              spec.str(), TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Missing closing '}' in type specification");
        }

        i += 1;
        if (!struct_type) {
          return llvm::StructType::get(llvm_context, elem_types);
        } else {
          struct_type->setBody(elem_types);
          return struct_type;
        }
      }

      // Parse an array type.
      case '[': {
        i += 1;
        auto maybe_elem_type =
            ParseType(llvm_context, ids, size_checked, spec, i);
        if (!maybe_elem_type.Succeeded()) {
          return maybe_elem_type.TakeError();
        }

        llvm::Type *elem_type = maybe_elem_type.TakeValue();
        if (!elem_type->isSized(&size_checked)) {
          return CreateError(
              spec.str(), TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Cannot create array with unsized element type (e.g. void or function type) in type specification");
        }
        if (i >= spec.size() || 'x' != spec[i]) {
          return CreateError(
              spec.str(), TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Missing 'x' in array type specification");
        }

        i += 1;
        size_t num_elems = 0;
        if (!Parse(spec, i, isdigit, &num_elems)) {
          return CreateError(
              spec.str(), TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Unable to parse array size in type specification");
        }

        if (i >= spec.size() || ']' != spec[i]) {
          return CreateError(
              spec.str(), TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Missing closing ']' in type specification");
        }

        if (!num_elems) {
          return CreateError(
              spec.str(), TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Invalid zero-sized array in type specification");
        }

        i += 1;
        return llvm::ArrayType::get(elem_type, num_elems);
      }

      // Parse a vector type.
      case '<': {
        i += 1;
        auto maybe_elem_type =
            ParseType(llvm_context, ids, size_checked, spec, i);
        if (!maybe_elem_type.Succeeded()) {
          return maybe_elem_type.TakeError();
        }

        llvm::Type *elem_type = maybe_elem_type.TakeValue();
        if (!elem_type->isSized(&size_checked)) {
          return CreateError(
              spec.str(), TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Cannot create vector with unsized element type (e.g. void or function type) in type specification");
        }

        if (i >= spec.size() || 'x' != spec[i]) {
          return CreateError(
              spec.str(), TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Missing 'x' in vector type specification");
        }

        i += 1;
        unsigned num_elems = 0;
        if (!Parse(spec, i, isdigit, &num_elems)) {
          return CreateError(
              spec.str(), TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Unable to parse vector size in type specification");
        }

        if (!num_elems) {
          return CreateError(
              spec.str(), TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Invalid zero-sized vector in type specification");
        }

        if (i >= spec.size() || '>' != spec[i]) {
          return CreateError(
              spec.str(), TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Missing closing '>' in type specification");
        }

        i += 1;
        return llvm::FixedVectorType::get(elem_type, num_elems);
      }

      // Parse a pointer type.
      case '*': {
        i += 1;
        auto maybe_elem_type =
            ParseType(llvm_context, ids, size_checked, spec, i);
        if (!maybe_elem_type.Succeeded()) {
          return maybe_elem_type.TakeError();
        }

        llvm::Type *elem_type = maybe_elem_type.TakeValue();
        if (!elem_type) {
          return CreateError(
              spec.str(), TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Missing subtype for pointer type in type specification");
        }

        if (elem_type->isVoidTy()) {
          return llvm::IntegerType::getInt8PtrTy(llvm_context, 0);

        } else if (!elem_type->isFunctionTy() &&
                   !elem_type->isSized(&size_checked)) {
          return CreateError(
              spec.str(), TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Cannot create a pointer to an unsized type in type specification");

        } else {
          return llvm::PointerType::get(elem_type, 0);
        }
      }

      // Parse a function type.
      case '(': {
        llvm::SmallVector<llvm::Type *, 4> elem_types;
        for (i += 1; i < spec.size() && spec[i] != ')';) {
          auto maybe_elem_type =
              ParseType(llvm_context, ids, size_checked, spec, i);
          if (!maybe_elem_type.Succeeded()) {
            return maybe_elem_type.TakeError();
          }

          if (auto elem_type = maybe_elem_type.TakeValue()) {
            elem_types.push_back(elem_type);
          } else {
            break;
          }
        }

        // There always needs to be at least one parameter type and one
        // return type. Here are some examples:
        //
        //    In C:               Here:
        //    void foo(void)      (vv)
        //    int foo(void)       (vi)
        //    void foo(...)       (&v)
        //    int foo(int, ...)   (i&i)
        //    void foo(int, ...)  (i&v)
        //
        // Not valid: (v...v).
        if (elem_types.size() < 2) {
          return CreateError(
              spec.str(), TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Function types must have at least two internal types. E.g. '(vv)' for a function taking nothing and returning nothing, in type specification");
        }

        const auto ret_type = elem_types.pop_back_val();
        if (ret_type->isTokenTy()) {
          return CreateError(
              spec.str(), TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Cannot have a variadic return type in type specification");
        }

        // Second-to-last type can optionally be a token type, which is
        // a stand in for varargs.
        auto is_var_arg = false;
        if (elem_types.back()->isTokenTy()) {
          is_var_arg = true;
          elem_types.pop_back();

        // If second-to-last is a void type, then it must be the first.
        } else if (elem_types.back()->isVoidTy()) {
          if (1 == elem_types.size()) {
            elem_types.pop_back();
          } else {
            return CreateError(
                spec.str(),
                TypeSpecificationError::ErrorCode::InvalidSpecFormat,
                "Invalid placement of void parameter type in type specification");
          }
        }

        // Minor sanity checking on the param types.
        for (auto param_type : elem_types) {
          if (param_type->isVoidTy() || param_type->isTokenTy() ||
              param_type->isFunctionTy()) {
            return CreateError(
                spec.str(),
                TypeSpecificationError::ErrorCode::InvalidSpecFormat,
                "Invalid parameter type in type specification");
          }
        }

        if (i >= spec.size() || ')' != spec[i]) {
          return CreateError(
              spec.str(), TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Missing closing ')' in type specification");
        }

        i += 1;
        return llvm::FunctionType::get(ret_type, elem_types, is_var_arg);
      }

      // Parse a varargs type, and represent it as a token type.
      case '&': {
        i += 1;
        return llvm::Type::getTokenTy(llvm_context);
      }

      // Parse an assignment of a type ID (local to this specification) for later
      // use, e.g. to do a linked list of `int`s, you would do:
      //
      //    In C:                 Here:
      //    struct LI32 {         =0{*%0i}
      //      struct LI32 *next;
      //      int val;
      //    };
      //
      // This also enables some compression, e.g.:
      //
      //    In C:                 Here:
      //    struct P {            {ii}
      //      int x, y;
      //    };
      //    struct PP {           {{ii}{ii}}
      //      struct P x, y;          or
      //    };                    {=0{ii}%0}
      case '=': {
        i += 1;
        unsigned type_id = 0;
        if (!Parse(spec, i, isdigit, &type_id)) {
          return CreateError(
              spec.str(), TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Unable to parse type ID in type specification");
        }

        if (type_id != ids.size()) {
          std::stringstream message;
          message << "Invalid type ID assignment '" << type_id
                  << "'; next expected type ID was '"
                  << static_cast<unsigned>(ids.size()) << "'";

          return CreateError(
              spec.str(), TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              message.str());
        }

        if (i >= spec.size() || spec[i] != '{') {
          std::stringstream message;
          message << "Non-structure type assigned to type ID '" << type_id
                  << "'";

          return CreateError(
              spec.str(), TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              message.str());
        }

        std::stringstream ss;
        ss << "anvill.struct." << type_id;
        struct_type = llvm::StructType::create(llvm_context, ss.str());
        ids.push_back(struct_type);

        // Jump to the next iteration, which will parse the struct.
        continue;
      }

      // Parse a use of a type ID.
      case '%': {
        i += 1;
        unsigned type_id = 0;
        if (!Parse(spec, i, isdigit, &type_id)) {
          return CreateError(
              spec.str(), TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Unable to parse type ID in type specification");
        }

        if (type_id >= ids.size()) {
          std::stringstream message;
          message << "Invalid type ID use '" << type_id << "'";

          return CreateError(
              spec.str(), TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              message.str());
        }

        return ids[type_id];
      }

      case '?':  // bool, _Bool.
      case 'b':  // int8_t.
      case 'B':  // uint8_t.
        i += 1;
        return llvm::IntegerType::getInt8Ty(llvm_context);
      case 'h':  // int16_t.
      case 'H':  // uint16_t.
        i += 1;
        return llvm::IntegerType::getInt16Ty(llvm_context);
      case 'i':  // int32_t.
      case 'I':  // uint32_t.
        i += 1;
        return llvm::IntegerType::getInt32Ty(llvm_context);
      case 'l':  // int64_t.
      case 'L':  // uint64_t.
        i += 1;
        return llvm::IntegerType::getInt64Ty(llvm_context);
      case 'o':  // int128_t.
      case 'O':  // uint128_t.
        i += 1;
        return llvm::IntegerType::getInt128Ty(llvm_context);
      case 'e':  // float16_t`.
        i += 1;
        return llvm::Type::getHalfTy(llvm_context);
      case 'f':  // float.
        i += 1;
        return llvm::Type::getFloatTy(llvm_context);
      case 'd':  // double.
        i += 1;
        return llvm::Type::getDoubleTy(llvm_context);
      case 'D':  // long double.
        i += 1;
        return llvm::Type::getX86_FP80Ty(llvm_context);
      case 'M':  // MMX type.
        i += 1;
        return llvm::Type::getX86_MMXTy(llvm_context);
      case 'Q':  // Quad-precision float.
        i += 1;
        return llvm::Type::getFP128Ty(llvm_context);
      case 'v':  // void.
        i += 1;
        return llvm::Type::getVoidTy(llvm_context);

      default: {
        i += 1;

        std::stringstream message;
        message << "Unexpected character '" << spec[i - 1] << "'";

        return CreateError(spec.str(),
                           TypeSpecificationError::ErrorCode::InvalidSpecFormat,
                           message.str());
      }
    }
  }
  return nullptr;
}

Result<TypeSpecification::Context, TypeSpecificationError>
TypeSpecification::ParseSpec(llvm::LLVMContext &llvm_context,
                             llvm::StringRef spec) {

  std::vector<llvm::Type *> ids;
  size_t i = 0;
  llvm::SmallPtrSet<llvm::Type *, 8> size_checked;

  auto type_res = ParseType(llvm_context, ids, size_checked, spec, i);
  if (!type_res.Succeeded()) {
    return type_res.TakeError();
  }

  Context context;
  context.type = type_res.TakeValue();
  context.spec = spec.str();
  context.description = remill::LLVMThingToString(context.type);

  if (i < spec.size()) {
    return CreateError(spec.str(),
                       TypeSpecificationError::ErrorCode::InvalidState,
                       "Found trailing unparsed characters");
  }

  context.sized = context.type->isSized(&size_checked);
  return context;
}

Result<ITypeSpecification::Ptr, TypeSpecificationError>
ITypeSpecification::Create(llvm::LLVMContext &llvm_context,
                           llvm::StringRef spec) {
  try {
    return Ptr(new TypeSpecification(llvm_context, spec));

  } catch (const std::bad_alloc &) {
    TypeSpecificationError error;
    error.error_code =
        TypeSpecificationError::ErrorCode::MemoryAllocationFailure;

    return error;

  } catch (const TypeSpecificationError &error) {
    return error;
  }
}

}  // namespace anvill
