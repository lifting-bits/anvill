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

#include <anvill/TypeSpecification.h>

// clang-format off
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Type.h>
#include <llvm/Support/Error.h>
// clang-format on

#include <glog/logging.h>

#include <remill/BC/Compat/Error.h>
#include <remill/BC/Compat/VectorType.h>
#include <remill/BC/Util.h>

#include <sstream>
#include <unordered_map>
#include <vector>

namespace anvill {

class TypeSpecifierImpl {
 public:
  llvm::LLVMContext &context;
  const llvm::DataLayout dl;
  std::unordered_map<llvm::StructType *, size_t> type_to_id;
  std::vector<llvm::StructType *> id_to_type;

  inline TypeSpecifierImpl(llvm::LLVMContext &context_,
                           const llvm::DataLayout &dl_)
      : context(context_),
        dl(dl_) {}

  // Translates an llvm::Type to a type that conforms to the spec in
  // TypeSpecification.cpp
  void TranslateTypeInternal(llvm::Type &type, std::stringstream &ss,
                             bool alphanum);

  template <typename Filter, typename T>
  bool Parse(llvm::StringRef spec, size_t &i, Filter filter,
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


  Result<llvm::Type *, TypeSpecificationError>
  ParseType(llvm::SmallPtrSetImpl<llvm::Type *> &size_checked,
            llvm::StringRef spec, size_t &i);
};

// Translates an llvm::Type to a type that conforms to the spec in
// TypeSpecification.cpp
void TypeSpecifierImpl::TranslateTypeInternal(
    llvm::Type &type, std::stringstream &ss, bool alphanum) {
  switch (type.getTypeID()) {
    case llvm::Type::VoidTyID: ss << 'v'; break;

    case llvm::Type::HalfTyID: ss << 'e'; break;

    case llvm::Type::FloatTyID: ss << 'f'; break;

    case llvm::Type::DoubleTyID: ss << 'd'; break;

    case llvm::Type::FP128TyID: ss << 'Q'; break;

    case llvm::Type::X86_FP80TyID: ss << 'D'; break;

    case llvm::Type::X86_MMXTyID: ss << 'M'; break;


    case llvm::Type::IntegerTyID: {
      const auto derived = llvm::cast<llvm::IntegerType>(&type);

      // TODO(aty): Try to distinguish between uint and int. This is a bit
      //            complicated because LLVM doesn't make this distinction in
      //            its types. It does however, make a distinction between the
      //            operations used on signed vs unsigned integers. One idea is
      //            to look for these attributes or operations to try to deduce
      //            the signedness.
      //
      //            For example, we could look for 'div' vs. 'sdiv'.
      //
      //            Tracked: https://github.com/lifting-bits/anvill/issues/16
      auto sign = true;
      const auto bit_width = derived->getBitWidth();
      if (8u >= bit_width) {
        ss << (sign ? 'b' : 'B');

      } else if (16u >= bit_width) {
        ss << (sign ? 'h' : 'H');

      } else if (32u >= bit_width) {
        ss << (sign ? 'i' : 'I');

      } else if (64u >= bit_width) {
        ss << (sign ? 'l' : 'L');

      } else if (128u >= bit_width) {
        ss << (sign ? 'o' : 'O');

      } else {
        LOG(ERROR)
            << "Could not find an appropriate integer representation for "
            << remill::LLVMThingToString(derived);

        const auto num_bytes = (bit_width + 7u) / 8u;
        ss << (alphanum ? "_C" : "[") << "Bx" << num_bytes
           << (alphanum ? "_D" : "]");
      }

      break;
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
    case llvm::Type::FunctionTyID: {
      auto func_ptr = llvm::cast<llvm::FunctionType>(&type);
      ss << (alphanum ? "_A" : "(");

      for (llvm::Type *param : func_ptr->params()) {
        TranslateTypeInternal(*param, ss, alphanum);
      }

      if (func_ptr->isVarArg()) {
        ss << (alphanum ? "_V" : "&");
      } else if (!func_ptr->getNumParams()) {
        ss << 'v';
      }

      TranslateTypeInternal(*func_ptr->getReturnType(), ss, alphanum);
      ss << (alphanum ? "_B" : ")");
      break;
    }

    case llvm::Type::StructTyID: {
      auto struct_ptr = llvm::cast<llvm::StructType>(&type);

      // This is an opaque structure; mark it as a void type.
      if (struct_ptr->isOpaque()) {
        ss << 'v';
        break;
      }

      // If we're already serialized this structure type, or if we're inside
      // of the structure type, then use a back reference to avoid infinite
      // recursion.
      if (type_to_id.count(struct_ptr)) {
        ss << (alphanum ? "_M" : "%") << type_to_id[struct_ptr];

      // We've not yet serialized this structure.
      } else {

        // Start by emitting a new structure ID for this structure and memoizing
        // it to prevent infinite recursion (e.g. on linked lists).
        type_to_id[struct_ptr] = type_to_id.size();
        ss << (alphanum ? "_X" : "=") << type_to_id[struct_ptr]
           << (alphanum ? "_E" : "{");

        auto layout = dl.getStructLayout(struct_ptr);
        uint64_t expected_offset = 0u;
        for (unsigned i = 0, num_elems = struct_ptr->getNumElements();
             i < num_elems; ++i) {
          const auto offset = layout->getElementOffset(i);

          // There was some padding before this element.
          if (expected_offset < offset) {
            const auto diff = offset - expected_offset;
            if (diff == 1u) {
              ss << 'B';
            } else {
              ss << (alphanum ? "_C" : "[") << "Bx" << diff
                 << (alphanum ? "_D" : "]");
            }

          // TODO(pag): Investigate this possibility. Does this occur for
          //            bitfields?
          } else if (expected_offset > offset) {
          }

          const auto el_ty = struct_ptr->getElementType(i);
          TranslateTypeInternal(*el_ty, ss, alphanum);
          expected_offset = offset + dl.getTypeStoreSize(el_ty);
        }

        // Padding at the end of the structure. This could be due to alignment.
        const auto aligned_size = dl.getTypeAllocSize(struct_ptr);
        if (expected_offset < aligned_size) {
          const auto diff = aligned_size - expected_offset;
          if (diff == 1u) {
            ss << 'B';
          } else {
            ss << (alphanum ? "_C" : "[") << "Bx" << diff
               << (alphanum ? "_D" : "]");
          }
        }
        ss << (alphanum ? "_F" : "}");
      }
      break;
    }

    case llvm::GetFixedVectorTypeId(): {
      const auto vec_ptr = llvm::cast<llvm::FixedVectorType>(&type);
      ss << (alphanum ? "_G" : "<");
      TranslateTypeInternal(*vec_ptr->getElementType(), ss, alphanum);
      ss << 'x' << vec_ptr->getNumElements() << (alphanum ? "_H" : ">");
      break;
    }

    case llvm::Type::ArrayTyID: {
      const auto array_ptr = llvm::cast<llvm::ArrayType>(&type);
      ss << (alphanum ? "_C" : "[");
      TranslateTypeInternal(*array_ptr->getElementType(), ss, alphanum);
      ss << 'x' << array_ptr->getNumElements() << (alphanum ? "_D" : "]");
      break;
    }

    case llvm::Type::PointerTyID: {
      ss << (alphanum ? "_S" : "*");
      auto derived = llvm::dyn_cast<llvm::PointerType>(&type);
      auto elem_type = derived->getElementType();

      // Get the type of the pointee.
      if (elem_type->isSized()) {
        TranslateTypeInternal(*elem_type, ss, alphanum);

      // It's an opaque type, e.g. a structure that is declared but not defined.
      } else {
        ss << 'v';
      }
      break;
    }

    default: {

      // Approximate the type by making an array of bytes of a similar size. If
      // the type has padding due to alignment then we fake a structure and
      // split out the padding from the main data.
      const auto type_size = dl.getTypeStoreSize(&type);
      const auto aligned_size = dl.getTypeAllocSize(&type);
      if (aligned_size > type_size) {
        ss << (alphanum ? "_E_C" : "{[") << "Bx" << type_size
           << (alphanum ? "_D_C" : "][") << "Bx" << (aligned_size - type_size)
           << (alphanum ? "_D_F" : "]}");
      } else {
        ss << (alphanum ? "_C" : "[") << "Bx" << type_size
           << (alphanum ? "_D" : "]");
      }
    }
  }
}

Result<llvm::Type *, TypeSpecificationError>
TypeSpecifierImpl::ParseType(llvm::SmallPtrSetImpl<llvm::Type *> &size_checked,
                             llvm::StringRef spec, size_t &i) {

  llvm::StructType *struct_type = nullptr;
  const auto spec_size = spec.size();
  while (i < spec_size) {
    auto ch = spec[i];
    switch (ch) {

      // Parse a structure type.
      case '{': {
        llvm::SmallVector<llvm::Type *, 4> elem_types;
        for (i += 1; i < spec_size && spec[i] != '}';) {
          auto maybe_elem_type = ParseType(size_checked, spec, i);
          if (!maybe_elem_type.Succeeded()) {
            return maybe_elem_type.TakeError();
          }

          if (auto elem_type = maybe_elem_type.Value()) {
            if (!elem_type->isSized(&size_checked)) {
              return TypeSpecificationError{
                  TypeSpecificationError::ErrorCode::InvalidSpecFormat,
                  "Cannot create structure with an unsized element type (e.g. void or function type) in type specification"};
            }

            elem_types.push_back(elem_type);
          } else {
            break;
          }
        }

        if (elem_types.empty()) {
          return TypeSpecificationError{
              TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Invalid structure in type specification"};
        }

        if (i >= spec_size || '}' != spec[i]) {
          return TypeSpecificationError{
            TypeSpecificationError::ErrorCode::InvalidSpecFormat,
            "Missing closing '}' in type specification"};
        }

        i += 1;
        if (!struct_type) {
          return llvm::StructType::get(context, elem_types);
        } else {
          struct_type->setBody(elem_types);
          return struct_type;
        }
      }

      // Parse an array type.
      case '[': {
        i += 1;
        auto maybe_elem_type = ParseType(size_checked, spec, i);
        if (!maybe_elem_type.Succeeded()) {
          return maybe_elem_type.TakeError();
        }

        llvm::Type *elem_type = maybe_elem_type.TakeValue();
        if (!elem_type->isSized(&size_checked)) {
          return TypeSpecificationError{
              TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Cannot create array with unsized element type (e.g. void or function type) in type specification"};
        }
        if (i >= spec_size || 'x' != spec[i]) {
          return TypeSpecificationError{
              TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Missing 'x' in array type specification"};
        }

        i += 1;
        size_t num_elems = 0;
        if (!Parse(spec, i, isdigit, &num_elems)) {
          return TypeSpecificationError{
              TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Unable to parse array size in type specification"};
        }

        if (i >= spec_size || ']' != spec[i]) {
          return TypeSpecificationError{
              TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Missing closing ']' in type specification"};
        }

        // An array can be of size `0` used in the variable length object. The specs for
        // them will have size zero. e.g:
        //     struct dir {
        //        int32_t fd;           *=0{ii[bx0]}
        //        int32_t errcode;
        //        char data[0x0];
        //     };
        //
        // Don't throw error if the number of elements is zero.

        LOG_IF(INFO, !num_elems)
            << "Zero-sized array in type specification " << spec.str();

        i += 1;
        return llvm::ArrayType::get(elem_type, num_elems);
      }

      // Parse a vector type.
      case '<': {
        i += 1;
        auto maybe_elem_type = ParseType(size_checked, spec, i);
        if (!maybe_elem_type.Succeeded()) {
          return maybe_elem_type.TakeError();
        }

        llvm::Type *elem_type = maybe_elem_type.TakeValue();
        if (!elem_type->isSized(&size_checked)) {
          return TypeSpecificationError{
              TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Cannot create vector with unsized element type (e.g. void or function type) in type specification"};
        }

        if (i >= spec_size || 'x' != spec[i]) {
          return TypeSpecificationError{
              TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Missing 'x' in vector type specification"};
        }

        i += 1;
        unsigned num_elems = 0;
        if (!Parse(spec, i, isdigit, &num_elems)) {
          return TypeSpecificationError{
              TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Unable to parse vector size in type specification"};
        }

        if (!num_elems) {
          return TypeSpecificationError{
              TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Invalid zero-sized vector in type specification"};
        }

        if (i >= spec_size || '>' != spec[i]) {
          return TypeSpecificationError{
              TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Missing closing '>' in type specification"};
        }

        i += 1;
        return llvm::FixedVectorType::get(elem_type, num_elems);
      }

      // Parse a pointer type.
      case '*': {
        i += 1;
        auto maybe_elem_type = ParseType(size_checked, spec, i);
        if (!maybe_elem_type.Succeeded()) {
          return maybe_elem_type.TakeError();
        }

        llvm::Type *elem_type = maybe_elem_type.TakeValue();
        if (!elem_type) {
          return TypeSpecificationError{
              TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Missing subtype for pointer type in type specification"};
        }

        if (elem_type->isVoidTy()) {
          return llvm::IntegerType::getInt8PtrTy(context, 0);

        } else {

          // The element type of a pointer could an unsized type as well. Get the
          // pointer type from the element
          return llvm::PointerType::get(elem_type, 0);
        }
      }

      // Parse a function type.
      case '(': {
        llvm::SmallVector<llvm::Type *, 4> elem_types;
        for (i += 1; i < spec_size && spec[i] != ')';) {
          auto maybe_elem_type = ParseType(size_checked, spec, i);
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
          return TypeSpecificationError{
              TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Function types must have at least two internal types. E.g. '(vv)' for a function taking nothing and returning nothing, in type specification"};
        }

        const auto ret_type = elem_types.pop_back_val();
        if (ret_type->isTokenTy()) {
          return TypeSpecificationError{
              TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Cannot have a variadic return type in type specification"};
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
            return TypeSpecificationError{
                TypeSpecificationError::ErrorCode::InvalidSpecFormat,
                "Invalid placement of void parameter type in type specification"};
          }
        }

        // Minor sanity checking on the param types.
        for (auto param_type : elem_types) {
          if (param_type->isVoidTy() || param_type->isTokenTy() ||
              param_type->isFunctionTy()) {
            return TypeSpecificationError{
                TypeSpecificationError::ErrorCode::InvalidSpecFormat,
                "Invalid parameter type in type specification"};
          }
        }

        if (i >= spec.size() || ')' != spec[i]) {
          return TypeSpecificationError{
              TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Missing closing ')' in type specification"};
        }

        i += 1;
        return llvm::FunctionType::get(ret_type, elem_types, is_var_arg);
      }

      // Parse a varargs type, and represent it as a token type.
      case '&': {
        i += 1;
        return llvm::Type::getTokenTy(context);
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
          return TypeSpecificationError{
              TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Unable to parse type ID in type specification"};
        }

        if (type_id != id_to_type.size()) {
          std::stringstream message;
          message << "Invalid type ID assignment '" << type_id
                  << "'; next expected type ID was '"
                  << static_cast<unsigned>(id_to_type.size()) << "'";

          return TypeSpecificationError{
              TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              message.str()};
        }

        if (i >= spec_size || spec[i] != '{') {
          std::stringstream message;
          message << "Non-structure type assigned to type ID '" << type_id
                  << "'";

          return TypeSpecificationError{
              TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              message.str()};
        }

        struct_type = llvm::StructType::create(context);
        id_to_type.push_back(struct_type);

        // Jump to the next iteration, which will parse the struct.
        continue;
      }

      // Parse a use of a type ID.
      case '%': {
        i += 1;
        unsigned type_id = 0;
        if (!Parse(spec, i, isdigit, &type_id)) {
          return TypeSpecificationError{
              TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Unable to parse type ID in type specification"};
        }

        if (type_id >= id_to_type.size()) {
          std::stringstream message;
          message << "Invalid type ID use '" << type_id << "'";

          return TypeSpecificationError{
              TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              message.str()};
        } else {
          return id_to_type[type_id];
        }
      }

      case '?':  // bool, _Bool.
      case 'b':  // int8_t.
      case 'B':  // uint8_t.
        i += 1;
        return llvm::IntegerType::getInt8Ty(context);
      case 'h':  // int16_t.
      case 'H':  // uint16_t.
        i += 1;
        return llvm::IntegerType::getInt16Ty(context);
      case 'i':  // int32_t.
      case 'I':  // uint32_t.
        i += 1;
        return llvm::IntegerType::getInt32Ty(context);
      case 'l':  // int64_t.
      case 'L':  // uint64_t.
        i += 1;
        return llvm::IntegerType::getInt64Ty(context);
      case 'o':  // int128_t.
      case 'O':  // uint128_t.
        i += 1;
        return llvm::IntegerType::getInt128Ty(context);
      case 'e':  // float16_t`.
        i += 1;
        return llvm::Type::getHalfTy(context);
      case 'f':  // float.
        i += 1;
        return llvm::Type::getFloatTy(context);
      case 'd':  // double.
        i += 1;
        return llvm::Type::getDoubleTy(context);
      case 'D':  // long double.
        i += 1;
        return llvm::Type::getX86_FP80Ty(context);
      case 'M':  // MMX type.
        i += 1;
        return llvm::Type::getX86_MMXTy(context);
      case 'Q':  // Quad-precision float.
        i += 1;
        return llvm::Type::getFP128Ty(context);
      case 'v':  // void.
        i += 1;
        return llvm::Type::getVoidTy(context);

      default: {
        i += 1;

        std::stringstream message;
        message << "Unexpected character '" << spec[i - 1] << "'";

        return TypeSpecificationError{
            TypeSpecificationError::ErrorCode::InvalidSpecFormat,
            message.str()};
      }
    }
  }
  return nullptr;
}

TypeSpecifier::~TypeSpecifier(void) {}

TypeSpecifier::TypeSpecifier(llvm::LLVMContext &context,
                             const llvm::DataLayout &dl)
    : impl(std::make_unique<TypeSpecifierImpl>(context, dl)) {}

// Convert the type `type` to a string encoding. If `alphanum` is `true`
// then only alphanumeric characters (and underscores) are used. The
// alphanumeric representation is always safe to use when appended to
// identifier names.
std::string TypeSpecifier::EncodeToString(
    const llvm::Type *type, bool alphanum) const {
  std::stringstream ss;
  if (type) {
    impl->type_to_id.clear();
    impl->TranslateTypeInternal(*const_cast<llvm::Type *>(type), ss, alphanum);
  }
  return ss.str();
}

// Parse an encoded type string into its represented type.
Result<llvm::Type *, TypeSpecificationError>
TypeSpecifier::DecodeFromString(const std::string_view spec) {
  std::string decoded;
  const auto len = spec.size();
  decoded.reserve(len);
  for (auto i = 0ul; i < len; ++i) {
    auto ch = spec[i];

    switch (ch) {

      // An underscore is a prefix to re-interpret the subsequent letter/digit
      // as a different character. This lets us have a type encoding that is
      // purely alphanumeric, and thus well-suited toward embedding in symbol
      // names.
      case '_':
        if ((i + 1u) >= len) {
          decoded.push_back('_');

        } else {
          switch (spec[++i]) {

            // `_M` -> `%`.
            case 'M':
              decoded.push_back('%');
              break;

            // `_S` -> `*`.
            case 'S':
              decoded.push_back('*');
              break;

            // `_A` -> `(`.
            case 'A':
              decoded.push_back('(');
              break;

            // `_B` -> `)`.
            case 'B':
              decoded.push_back(')');
              break;

            // `_C` -> `[`.
            case 'C':
              decoded.push_back('[');
              break;

            // `_D` -> `]`.
            case 'D':
              decoded.push_back(']');
              break;

            // `_E` -> `{`.
            case 'E':
              decoded.push_back('{');
              break;

            // `_F` -> `}`.
            case 'F':
              decoded.push_back('}');
              break;

            // `_G` -> `<`.
            case 'G':
              decoded.push_back('<');
              break;

            // `_H` -> `>`.
            case 'H':
              decoded.push_back('>');
              break;

            // `_V` -> `&`.
            case 'V':
              decoded.push_back('&');
              break;

            // `_X` -> `=`.
            case 'X':
              decoded.push_back('=');
              break;

            default:
              decoded.push_back('_');
              decoded.push_back(ch);
              break;
          }
        }
        break;
      default:
        decoded.push_back(ch);
        break;
    }
  }

  size_t i = 0;
  llvm::SmallPtrSet<llvm::Type *, 8> size_checked;
  impl->id_to_type.clear();
  return impl->ParseType(size_checked, spec, i);
}

}  // namespace anvill
