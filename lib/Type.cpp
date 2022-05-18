/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Type.h>

#define ANVILL_USE_WRAPPED_TYPES 0

// clang-format off
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Type.h>
#include <llvm/Support/Error.h>
// clang-format on

#include <glog/logging.h>

#include <remill/Arch/Arch.h>
#include <remill/BC/Compat/Error.h>
#include <remill/BC/Compat/VectorType.h>
#include <remill/BC/Util.h>

#include <anvill/ABI.h>
#include <anvill/Utils.h>

#include <sstream>
#include <unordered_map>
#include <vector>

namespace anvill {

class TypeSpecifierImpl {
 public:
  llvm::LLVMContext &context;
  const llvm::DataLayout dl;
  const TypeDictionary type_dict;
  std::unordered_map<llvm::StructType *, size_t> type_to_id;
  std::vector<llvm::StructType *> id_to_type;

  inline TypeSpecifierImpl(const TypeDictionary &type_dict_,
                           const llvm::DataLayout &dl_)
      : context(type_dict_.u.named.bool_->getContext()),
        dl(dl_),
        type_dict(type_dict_) {}

  // Translates an llvm::Type to a type that conforms to the spec in
  // TypeSpecification.cpp
  void EncodeType(llvm::Type &type, std::stringstream &ss,
                  EncodingFormat format);

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
void TypeSpecifierImpl::EncodeType(
    llvm::Type &type, std::stringstream &ss, EncodingFormat format) {
  const auto alpha_num = format == EncodingFormat::kValidSymbolCharsOnly;
  switch (type.getTypeID()) {
    case llvm::Type::VoidTyID: ss << 'v'; break;
    case llvm::Type::HalfTyID: ss << 'e'; break;
    case llvm::Type::FloatTyID: ss << 'f'; break;
    case llvm::Type::DoubleTyID: ss << 'F'; break;
    case llvm::Type::FP128TyID: ss << 'Q'; break;
    case llvm::Type::X86_FP80TyID:
      if (dl.getTypeAllocSize(&type) == 12) {
        ss << 'd';
      } else {
        ss << 'D';
      }
      break;
    case llvm::Type::X86_MMXTyID: ss << 'M'; break;
    case llvm::Type::IntegerTyID: {
      const auto derived = llvm::cast<llvm::IntegerType>(&type);
      constexpr auto sign = false;
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
        ss << (alpha_num ? "_C" : "[") << "Bx" << num_bytes
           << (alpha_num ? "_D" : "]");
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
      ss << (alpha_num ? "_A" : "(");

      for (llvm::Type *param : func_ptr->params()) {
        EncodeType(*param, ss, format);
      }

      if (func_ptr->isVarArg()) {
        ss << (alpha_num ? "_V" : "&");
      } else if (!func_ptr->getNumParams()) {
        ss << 'v';
      }

      EncodeType(*func_ptr->getReturnType(), ss, format);
      ss << (alpha_num ? "_B" : ")");
      break;
    }

    case llvm::Type::StructTyID: {
      auto struct_ptr = llvm::cast<llvm::StructType>(&type);
      if (struct_ptr == type_dict.u.named.bool_) {
        ss << '?';
      } else if (struct_ptr == type_dict.u.named.char_) {
        ss << 'c';
      } else if (struct_ptr == type_dict.u.named.schar) {
        ss << 's';
      } else if (struct_ptr == type_dict.u.named.uchar) {
        ss << 'S';
      } else if (struct_ptr == type_dict.u.named.int8) {
        ss << 'b';
      } else if (struct_ptr == type_dict.u.named.uint8) {
        ss << 'B';
      } else if (struct_ptr == type_dict.u.named.int16) {
        ss << 'h';
      } else if (struct_ptr == type_dict.u.named.uint16) {
        ss << 'H';
      } else if (struct_ptr == type_dict.u.named.int24) {
        ss << 'w';
      } else if (struct_ptr == type_dict.u.named.uint24) {
        ss << 'W';
      } else if (struct_ptr == type_dict.u.named.int32) {
        ss << 'i';
      } else if (struct_ptr == type_dict.u.named.uint32) {
        ss << 'I';
      } else if (struct_ptr == type_dict.u.named.int64) {
        ss << 'l';
      } else if (struct_ptr == type_dict.u.named.uint64) {
        ss << 'L';
      } else if (struct_ptr == type_dict.u.named.int128) {
        ss << 'o';
      } else if (struct_ptr == type_dict.u.named.uint128) {
        ss << 'O';
      } else if (struct_ptr == type_dict.u.named.float16) {
        ss << 'e';
      } else if (struct_ptr == type_dict.u.named.float32) {
        ss << 'f';
      } else if (struct_ptr == type_dict.u.named.float64) {
        ss << 'F';
      } else if (struct_ptr == type_dict.u.named.float80_12) {
        ss << 'd';
      } else if (struct_ptr == type_dict.u.named.float80_16) {
        ss << 'D';
      } else if (struct_ptr == type_dict.u.named.float128) {
        ss << 'Q';
      } else if (struct_ptr == type_dict.u.named.m64) {
        ss << 'M';
      } else if (struct_ptr == type_dict.u.named.void_) {
        ss << 'v';
      } else if (struct_ptr == type_dict.u.named.padding) {
        ss << 'p';

      // This is an opaque structure; mark it as a void type.
      } else if (struct_ptr->isOpaque()) {
        ss << 'v';

      } else {

        // If we're already serialized this structure type, or if we're inside
        // of the structure type, then use a back reference to avoid infinite
        // recursion.
        if (type_to_id.count(struct_ptr)) {
          ss << (alpha_num ? "_M" : "%") << type_to_id[struct_ptr];

        // We've not yet serialized this structure.
        } else {

          // Start by emitting a new structure ID for this structure and memoizing
          // it to prevent infinite recursion (e.g. on linked lists).
          type_to_id[struct_ptr] = type_to_id.size();
          ss << (alpha_num ? "_X" : "=") << type_to_id[struct_ptr]
             << (alpha_num ? "_E" : "{");

          auto layout = dl.getStructLayout(struct_ptr);
          uint64_t expected_offset = 0u;
          for (unsigned i = 0, num_elems = struct_ptr->getNumElements();
               i < num_elems; ++i) {
            const auto offset = layout->getElementOffset(i);

            // There was some padding before this element.
            if (expected_offset < offset) {
              const auto diff = offset - expected_offset;
              if (diff < 8u) {
                for (auto p = 0u; p < diff; ++p) {
                  ss << 'p';
                }
              } else {
                ss << (alpha_num ? "_C" : "[") << "px" << diff
                   << (alpha_num ? "_D" : "]");
              }

            // TODO(pag): Investigate this possibility. Does this occur for
            //            bitfields?
            } else if (expected_offset > offset) {
              LOG(FATAL) << "TODO?! Maybe bitfields? Structure field offset shenanigans";
            }

            const auto el_ty = struct_ptr->getElementType(i);
            EncodeType(*el_ty, ss, format);
            expected_offset = offset + dl.getTypeStoreSize(el_ty);
          }

          // Padding at the end of the structure. This could be due to alignment.
          const auto aligned_size = dl.getTypeAllocSize(struct_ptr);
          if (expected_offset < aligned_size) {
            const auto diff = aligned_size - expected_offset;
            if (diff < 8u) {
              for (auto p = 0u; p < diff; ++p) {
                ss << 'p';
              }
            } else {
              ss << (alpha_num ? "_C" : "[") << "px" << diff
                 << (alpha_num ? "_D" : "]");
            }
          }
          ss << (alpha_num ? "_F" : "}");
        }
      }
      break;
    }

    case llvm::GetFixedVectorTypeId(): {
      const auto vec_ptr = llvm::cast<llvm::FixedVectorType>(&type);
      ss << (alpha_num ? "_G" : "<");
      EncodeType(*vec_ptr->getElementType(), ss, format);
      ss << 'x' << vec_ptr->getNumElements() << (alpha_num ? "_H" : ">");
      break;
    }

    case llvm::Type::ArrayTyID: {
      const auto array_ptr = llvm::cast<llvm::ArrayType>(&type);
      ss << (alpha_num ? "_C" : "[");
      EncodeType(*array_ptr->getElementType(), ss, format);
      ss << 'x' << array_ptr->getNumElements() << (alpha_num ? "_D" : "]");
      break;
    }

    case llvm::Type::PointerTyID: ss << (alpha_num ? "_S" : "*"); break;

    default: {

      // Approximate the type by making an array of bytes of a similar size. If
      // the type has padding due to alignment then we fake a structure and
      // split out the padding from the main data.
      const auto type_size = dl.getTypeStoreSize(&type);
      const auto aligned_size = dl.getTypeAllocSize(&type);
      if (aligned_size > type_size) {
        ss << (alpha_num ? "_E_C" : "{[") << "Bx" << type_size
           << (alpha_num ? "_D_C" : "][") << "Bx" << (aligned_size - type_size)
           << (alpha_num ? "_D_F" : "]}");
      } else {
        ss << (alpha_num ? "_C" : "[") << "Bx" << type_size
           << (alpha_num ? "_D" : "]");
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
    switch (auto ch = spec[i]; ch) {

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
        return llvm::PointerType::get(this->context, 0);
      }

      // Parse a function type.
      case '(': {
        llvm::SmallVector<std::pair<unsigned, llvm::Type *>, 4> elem_types;
        for (i += 1; i < spec_size && spec[i] != ')';) {
          const auto prev_i = i;
          auto maybe_elem_type = ParseType(size_checked, spec, i);
          if (!maybe_elem_type.Succeeded()) {
            return maybe_elem_type.TakeError();
          }

          if (auto elem_type = maybe_elem_type.TakeValue()) {
            elem_types.emplace_back(prev_i, elem_type);
          } else {
            std::stringstream ss;
            ss << "Failed to parse argument/return type: "
               << spec.substr(prev_i).str();
            return TypeSpecificationError{
                TypeSpecificationError::ErrorCode::InvalidSpecFormat,
                ss.str()};
          }
        }

        if (i >= spec.size()) {
          return TypeSpecificationError{
              TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Missing closing ')' in type specification; "
              "fell off end before function type was finished"};

        } else if (')' != spec[i]) {
          std::stringstream ss;
          ss << "Expected ')' for end of function type, but got this: "
             << spec.substr(i).str();
          return TypeSpecificationError{
              TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              ss.str()};
        }

        // Skip over the `)`.
        i += 1;

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

        llvm::Type *ret_type = elem_types.pop_back_val().second;
#if ANVILL_USE_WRAPPED_TYPES
        if (ret_type == type_dict.u.named.void_) {
          ret_type = llvm::Type::getVoidTy(context);
        }
#endif
        if (ret_type->isTokenTy()) {
          return TypeSpecificationError{
              TypeSpecificationError::ErrorCode::InvalidSpecFormat,
              "Cannot have a variadic return type in type specification"};
        }

        // Second-to-last type can optionally be a token type, which is
        // a stand in for varargs.
        auto is_var_arg = false;
        if (elem_types.back().second->isTokenTy()) {
          is_var_arg = true;
          elem_types.pop_back();

        // If second-to-last is a void type, then it must be the first.
        } else if (elem_types.back().second->isVoidTy() ||
                   elem_types.back().second == type_dict.u.named.void_) {
          if (1 == elem_types.size()) {
            elem_types.pop_back();
          } else {
            std::stringstream ss;
            ss << "Invalid placement of void parameter type in type "
               << "specification: "
               << spec.substr(elem_types.back().first).str();
            return TypeSpecificationError{
                TypeSpecificationError::ErrorCode::InvalidSpecFormat,
                ss.str()};
          }
        }

        llvm::SmallVector<llvm::Type *, 4> param_types;

        // Minor sanity checking on the param types.
        for (auto [param_i, param_type] : elem_types) {
          if (param_type->isVoidTy() || param_type == type_dict.u.named.void_ ||
              param_type->isFunctionTy()) {
            std::stringstream ss;
            ss << "Invalid parameter type in type specification: "
               << spec.substr(param_i).str();
            return TypeSpecificationError{
                TypeSpecificationError::ErrorCode::InvalidSpecFormat,
                ss.str()};

          } else if (param_type->isTokenTy()) {
            std::stringstream ss;
            ss << "Unexpected variadic argument type in type specification: "
               << spec.substr(param_i).str();
            return TypeSpecificationError{
                TypeSpecificationError::ErrorCode::InvalidSpecFormat,
                ss.str()};
          } else {
            param_types.push_back(param_type);
          }
        }

        return llvm::FunctionType::get(ret_type, param_types, is_var_arg);
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
        i += 1;
        return type_dict.u.named.bool_;
      case 'c':  // char.
        i += 1;
        return type_dict.u.named.char_;
      case 's':  // signed char.
        i += 1;
        return type_dict.u.named.schar;
      case 'S':  // unsigned char.
        i += 1;
        return type_dict.u.named.uchar;
      case 'b':  // int8_t.
        i += 1;
        return type_dict.u.named.int8;
      case 'B':  // uint8_t.
        i += 1;
        return type_dict.u.named.uint8;
      case 'h':  // int16_t.
        i += 1;
        return type_dict.u.named.int16;
      case 'H':  // uint16_t.
        i += 1;
        return type_dict.u.named.uint16;
      case 'w':  // int24_t.
        i += 1;
        return type_dict.u.named.int24;
      case 'W':  // uint24_t.
        i += 1;
        return type_dict.u.named.uint24;
      case 'i':  // int32_t.
        i += 1;
        return type_dict.u.named.int32;
      case 'I':  // uint32_t.
        i += 1;
        return type_dict.u.named.uint32;
      case 'l':  // int64_t.
        i += 1;
        return type_dict.u.named.int64;
      case 'L':  // uint64_t.
        i += 1;
        return type_dict.u.named.uint64;
      case 'o':  // int128_t.
        i += 1;
        return type_dict.u.named.int128;
      case 'O':  // uint128_t.
        i += 1;
        return type_dict.u.named.uint128;
      case 'e':  // float16_t`.
        i += 1;
        return type_dict.u.named.float16;
      case 'f':  // float.
        i += 1;
        return type_dict.u.named.float32;
      case 'F':  // double.
        i += 1;
        return type_dict.u.named.float64;
      case 'd':  // long double.
        i += 1;
        return type_dict.u.named.float80_12;
      case 'D':  // long double.
        i += 1;
        return type_dict.u.named.float80_16;
      case 'M':  // MMX type.
        i += 1;
        return type_dict.u.named.m64;
      case 'Q':  // Quad-precision float.
        i += 1;
        return type_dict.u.named.float128;
      case 'v':  // void.
        i += 1;
        return type_dict.u.named.void_;
      case 'p':  // Padding.
        i += 1;
        return type_dict.u.named.padding;

      default: {
        i += 1;

        std::stringstream message;
        message << "Unexpected character '" << spec[i - 1u] << "'";

        return TypeSpecificationError{
            TypeSpecificationError::ErrorCode::InvalidSpecFormat,
            message.str()};
      }
    }
  }
  return TypeSpecificationError{
      TypeSpecificationError::ErrorCode::InvalidState,
      "Fell off the end of the type parser"};
}

namespace {

#if ANVILL_USE_WRAPPED_TYPES

template <typename T>
static llvm::Type *GetOrCreateWrapper(
    llvm::LLVMContext &context, const char *name, T wrapper) {
  std::string type_name = kAnvillNamePrefix + name;
  auto ty = llvm::StructType::getTypeByName(context, type_name);
  if (ty) {
    return ty;
  }

  llvm::Type *elems[] = {wrapper(context)};
  return llvm::StructType::create(context, elems, type_name, true);
}

static llvm::Type *GetOrCreateInt(llvm::LLVMContext &context,
                                  const char *name, unsigned num_bits) {
  return GetOrCreateWrapper(context, name, [=] (llvm::LLVMContext &context_) {
    return llvm::IntegerType::get(context_, num_bits);
  });
}

static llvm::Type *GetOrCreateFloat(llvm::LLVMContext &context,
                                  const char *name, unsigned num_bits) {
  return GetOrCreateWrapper(
      context, name, [=] (llvm::LLVMContext &context_) -> llvm::Type * {
        switch (num_bits) {
          case 16: return llvm::Type::getHalfTy(context_);
          case 32: return llvm::Type::getFloatTy(context_);
          case 64: return llvm::Type::getDoubleTy(context_);
          case 128: return llvm::Type::getFP128Ty(context_);
          default: return nullptr;
        }
      });
}

#endif

}  // namespace

TypeDictionary::TypeDictionary(llvm::LLVMContext &context) {
#if ANVILL_USE_WRAPPED_TYPES
  u.named.bool_ = GetOrCreateInt(context, "bool", 1);
  u.named.char_ = GetOrCreateInt(context, "char", 8);
  u.named.schar = GetOrCreateInt(context, "schar", 8);
  u.named.uchar = GetOrCreateInt(context, "uchar", 8);
  u.named.int8 = GetOrCreateInt(context, "int8", 8);
  u.named.uint8 = GetOrCreateInt(context, "uint8", 8);
  u.named.int16 = GetOrCreateInt(context, "int16", 16);
  u.named.uint16 = GetOrCreateInt(context, "uint16", 16);
  u.named.int32 = GetOrCreateInt(context, "int24", 24);
  u.named.uint32 = GetOrCreateInt(context, "uint24", 24);
  u.named.int32 = GetOrCreateInt(context, "int32", 32);
  u.named.uint32 = GetOrCreateInt(context, "uint32", 32);
  u.named.int64 = GetOrCreateInt(context, "int64", 64);
  u.named.uint64 = GetOrCreateInt(context, "uint64", 64);
  u.named.int128 = GetOrCreateInt(context, "int128", 128);
  u.named.uint128 = GetOrCreateInt(context, "uint128", 128);
  u.named.float16 = GetOrCreateFloat(context, "float16", 16);
  u.named.float32 = GetOrCreateFloat(context, "float32", 32);
  u.named.float64 = GetOrCreateFloat(context, "float64", 64);
  u.named.float80_12 = GetOrCreateWrapper(
      context, "float80_12", [] (llvm::LLVMContext &context_) {
        return llvm::ArrayType::get(llvm::Type::getInt8Ty(context_), 10);
      });
  u.named.float80_16 = GetOrCreateWrapper(
      context, "float80_16", [] (llvm::LLVMContext &context_) {
        return llvm::ArrayType::get(llvm::Type::getInt8Ty(context_), 12);
      });
  u.named.float128 = GetOrCreateFloat(context, "float128", 128);
  u.named.m64 = GetOrCreateWrapper(context, "mmx", [] (llvm::LLVMContext &context_) {
    return llvm::Type::getX86_MMXTy(context_);
  });
  u.named.void_ = GetOrCreateInt(context, "void", 8);
  u.named.padding = GetOrCreateInt(context, "padding", 8);
#else
  u.named.bool_ = llvm::Type::getInt8Ty(context);
  u.named.char_ = llvm::Type::getInt8Ty(context);
  u.named.schar = u.named.char_;
  u.named.uchar = u.named.char_;
  u.named.int8 = u.named.char_;
  u.named.uint8 = u.named.char_;
  u.named.int16 = llvm::Type::getInt16Ty(context);
  u.named.uint16 = u.named.int16;
  u.named.int24 = llvm::Type::getIntNTy(context, 24u);
  u.named.uint24 = u.named.int24;
  u.named.int32 = llvm::Type::getInt32Ty(context);
  u.named.uint32 = u.named.int32;
  u.named.int64 = llvm::Type::getInt64Ty(context);
  u.named.uint64 = u.named.int64;
  u.named.int128 = llvm::Type::getInt128Ty(context);
  u.named.uint128 = u.named.int128;
  u.named.float16 = llvm::Type::getHalfTy(context);
  u.named.float32 = llvm::Type::getFloatTy(context);
  u.named.float64 = llvm::Type::getDoubleTy(context);
  u.named.float80_12 = llvm::Type::getX86_FP80Ty(context);
  u.named.float80_16 = u.named.float80_12;
  u.named.float128 = llvm::Type::getFP128Ty(context);
  u.named.m64 = llvm::Type::getX86_MMXTy(context);
  u.named.void_ = llvm::Type::getVoidTy(context);
  u.named.padding = u.named.char_;
#endif
}

// Returns `true` if `type` is the padding type, or is entirely made up
// of padding bytes (e.g. an array of the padding type).
bool TypeDictionary::IsPadding(llvm::Type *type) const noexcept {
#if ANVILL_USE_WRAPPED_TYPES
  switch (type->getTypeID()) {
    case llvm::Type::StructTyID:
      for (auto elem_type : llvm::dyn_cast<llvm::StructType>(type)->elements()) {
        if (!IsPadding(elem_type)) {
          return false;
        }
      }
      return true;
    case llvm::Type::ArrayTyID: {
      auto elem_type = llvm::dyn_cast<llvm::ArrayType>(type)->getElementType();
      return IsPadding(elem_type);
    }
    case llvm::Type::FixedVectorTyID: {
      auto elem_type = llvm::dyn_cast<llvm::VectorType>(type)->getElementType();
      return IsPadding(elem_type);
    }
    default:
      return type == u.named.padding;
  }
#else
  return false;
#endif
}

TypeTranslator::~TypeTranslator(void) {}

TypeTranslator::TypeTranslator(const TypeDictionary &type_dict,
                             const llvm::DataLayout &dl)
    : impl(std::make_unique<TypeSpecifierImpl>(type_dict, dl)) {}

// Delegating constructor using a module's data layout.
TypeTranslator::TypeTranslator(const TypeDictionary &type_dict,
                               const llvm::Module &module)
    : TypeTranslator(type_dict, module.getDataLayout()) {}

// Delegating constructor using an architecture's data layout.
TypeTranslator::TypeTranslator(const TypeDictionary &type_dict,
                               const remill::Arch *arch)
    : TypeTranslator(type_dict, arch->DataLayout()) {}

TypeTranslator::TypeTranslator(const TypeDictionary &type_dict,
                               const std::unique_ptr<const remill::Arch> &arch)
    : TypeTranslator(type_dict, arch->DataLayout()) {}

// Return the type dictionary for this type specifier.
const TypeDictionary &TypeTranslator::Dictionary(void) const noexcept {
  return impl->type_dict;
}

// Return a reference to the data layout used by this type translator.
const llvm::DataLayout &TypeTranslator::DataLayout(void) const noexcept {
  return impl->dl;
}

// Convert the type `type` to a string encoding. If `alpha_num` is `true`
// then only alpha_numeric characters (and underscores) are used. The
// alpha_numeric representation is always safe to use when appended to
// identifier names.
std::string TypeTranslator::EncodeToString(
    llvm::Type *type, EncodingFormat format) const {
  std::stringstream ss;
  if (type) {
    impl->type_to_id.clear();
    impl->EncodeType(
        *remill::RecontextualizeType(type, impl->context), ss, format);
  }
  return ss.str();
}

// Parse an encoded type string into its represented type.
Result<llvm::Type *, TypeSpecificationError>
TypeTranslator::DecodeFromString(const std::string_view spec) const {
  std::string decoded;
  const auto len = spec.size();
  decoded.reserve(len);
  for (auto i = 0ul; i < len; ++i) {
    switch (auto ch = spec[i]; ch) {

      // An underscore is a prefix to re-interpret the subsequent letter/digit
      // as a different character. This lets us have a type encoding that is
      // purely alphanumeric, and thus well-suited toward embedding in symbol
      // names.
      case '_':
        ++i;
        if (i >= len) {
          decoded.push_back('_');

        } else {
          switch (const auto ch2 = spec[i]) {

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
              decoded.push_back(ch);
              decoded.push_back(ch2);
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

  auto ret = impl->ParseType(size_checked, decoded, i);
  if (i < decoded.size()) {
    std::stringstream ss;
    ss << "Trailing unparsed characters at end of type specification: "
       << decoded.substr(i);
    return TypeSpecificationError{
        TypeSpecificationError::ErrorCode::InvalidSpecFormat,
        ss.str()};
  } else {
    return ret;
  }
}

namespace {

static std::tuple<TypeKind, TypeSign, unsigned> kProfiles[] = {
    {TypeKind::kBoolean, TypeSign::kUnsigned, 1},  // bool_
    {TypeKind::kCharacter, TypeSign::kUnknown, 8},  // char_
    {TypeKind::kCharacter, TypeSign::kSigned, 8},  // schar
    {TypeKind::kCharacter, TypeSign::kUnsigned, 8},  // uchar
    {TypeKind::kIntegral, TypeSign::kSigned, 8},  // int8
    {TypeKind::kIntegral, TypeSign::kUnsigned, 8},  // uint8
    {TypeKind::kIntegral, TypeSign::kSigned, 16},  // int16
    {TypeKind::kIntegral, TypeSign::kUnsigned, 16},  // uint16
    {TypeKind::kIntegral, TypeSign::kSigned, 32},  // int32
    {TypeKind::kIntegral, TypeSign::kUnsigned, 32},  // uint32
    {TypeKind::kIntegral, TypeSign::kSigned, 64},  // int64
    {TypeKind::kIntegral, TypeSign::kUnsigned, 64},  // uint64
    {TypeKind::kIntegral, TypeSign::kSigned, 128},  // int128
    {TypeKind::kIntegral, TypeSign::kUnsigned, 128},  // uint128
    {TypeKind::kFloatingPoint, TypeSign::kSigned, 16},  // float16
    {TypeKind::kFloatingPoint, TypeSign::kSigned, 32},  // float32
    {TypeKind::kFloatingPoint, TypeSign::kSigned, 64},  // float64
    {TypeKind::kFloatingPoint, TypeSign::kSigned, 96},  // float80_12
    {TypeKind::kFloatingPoint, TypeSign::kSigned, 128},  // float80_16
    {TypeKind::kFloatingPoint, TypeSign::kSigned, 128},  // float128
    {TypeKind::kMMX, TypeSign::kUnknown, 64},  // m64
    {TypeKind::kVoid, TypeSign::kSigned, 0},  // void_
    {TypeKind::kVoid, TypeSign::kSigned, 8},  // padding_
};

template <unsigned kSize>
static std::optional<unsigned> FindTypeInList(
    llvm::Type *query, llvm::Type * const (&types)[kSize]) {
#if ANVILL_USE_WRAPPED_TYPES
  for (auto i = 0u; i < kSize; ++i) {
    if (types[i] == query) {
      return i;
    }
  }
#endif
  return std::nullopt;
}

}  // namespace

// Convert a value to a specific type.
llvm::Value *TypeDictionary::ConvertValueToType(
    llvm::IRBuilderBase &ir, llvm::Value *src_val,
    llvm::Type *dest_type) const {
  llvm::Type *src_type = src_val->getType();

  if (src_type == dest_type) {
    return src_val;
  }

  auto real_void_type = llvm::Type::getVoidTy(u.named.void_->getContext());
  CHECK_NE(src_type, u.named.void_);
  CHECK_NE(dest_type, u.named.void_);
  CHECK_NE(src_type, real_void_type);
  CHECK_NE(dest_type, real_void_type);

  auto maybe_src_type_index = FindTypeInList(src_type, u.indexed);
  auto maybe_dest_type_index = FindTypeInList(dest_type, u.indexed);

  // Unpack the source type, and then try to build it into the destination
  // type. This dispatches to the next case.
  if (maybe_src_type_index && maybe_dest_type_index) {
//    unsigned indexes[] = {0u};
//    auto dest_val = ir.CreateExtractValue(src_val, indexes);
//    CopyMetadataTo(src_val, dest_val);
//    return ConvertValueToType(ir, dest_val, dest_type);
    LOG(FATAL) << "TODO";
    return nullptr;

  // Pack this type into a destination structure type.
  } else if (!maybe_src_type_index && maybe_dest_type_index) {
    LOG(FATAL) << "TODO";
    return nullptr;

  // Unpack this type from a source structure type.
  } else if (maybe_src_type_index && !maybe_dest_type_index) {
    unsigned indexes[] = {0u};
    auto dest_val = ir.CreateExtractValue(src_val, indexes);
    CopyMetadataTo(src_val, dest_val);
    return AdaptToType(ir, dest_val, dest_type);

  // Raw type adaptation.
  } else {
    return AdaptToType(ir, src_val, dest_type);
  }
}

// Return the general type of a type, whether or not it is signed, and its
// size in bits.
std::tuple<TypeKind, TypeSign, unsigned> TypeDictionary::Profile(
    llvm::Type *type, const llvm::DataLayout &dl) {
  if (auto index = FindTypeInList(type, u.indexed)) {
    return kProfiles[*index];
  } else if (type->isIntegerTy()) {
    auto num_bits = type->getPrimitiveSizeInBits().getFixedSize();
    if (num_bits == 1u) {
      return {TypeKind::kBoolean, TypeSign::kUnsigned, 1};
    } else {
      return {TypeKind::kIntegral, TypeSign::kUnknown, num_bits};
    }
  } else if (type->isHalfTy()) {
    return {TypeKind::kFloatingPoint, TypeSign::kSigned, 16};
  } else if (type->isFloatTy()) {
    return {TypeKind::kFloatingPoint, TypeSign::kSigned, 32};
  } else if (type->isDoubleTy()) {
    return {TypeKind::kFloatingPoint, TypeSign::kSigned, 64};
  } else if (type->isFP128Ty()) {
    return {TypeKind::kFloatingPoint, TypeSign::kSigned, 128};
  } else if (type->isX86_FP80Ty()) {
    return {TypeKind::kFloatingPoint, TypeSign::kSigned,
            dl.getTypeAllocSizeInBits(type).getFixedSize()};
  } else if (type->isX86_MMXTy()) {
    return {TypeKind::kMMX, TypeSign::kUnknown, 64};
  } else if (type->isVoidTy()) {
    return {TypeKind::kVoid, TypeSign::kUnknown, 0};
  } else {
    return {TypeKind::kUnknown, TypeSign::kUnknown, 0};
  }
}

}  // namespace anvill
