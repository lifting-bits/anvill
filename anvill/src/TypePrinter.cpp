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

#include <anvill/TypePrinter.h>
#include <glog/logging.h>

// clang-format off
#include <remill/BC/Compat/CTypes.h>
#include <remill/BC/Compat/VectorType.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Type.h>

// clang-format on

#include <remill/BC/Util.h>

#include <sstream>
#include <unordered_map>

namespace anvill {
namespace {

// Translates an llvm::Type to a type that conforms to the spec in
// TypeParser.cpp
static void
TranslateTypeInternal(llvm::Type &type, std::stringstream &ss,
                      std::unordered_map<llvm::StructType *, size_t> &ids,
                      const llvm::DataLayout &dl, bool alphanum) {
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
        TranslateTypeInternal(*param, ss, ids, dl, alphanum);
      }

      if (func_ptr->isVarArg()) {
        ss << (alphanum ? "_V" : "&");
      } else if (!func_ptr->getNumParams()) {
        ss << 'v';
      }

      TranslateTypeInternal(*func_ptr->getReturnType(), ss, ids, dl, alphanum);
      ss << (alphanum ? "_B" : ")");
      break;
    }

    case llvm::Type::StructTyID: {
      auto struct_ptr = llvm::cast<llvm::StructType>(&type);

      // If we're already serialized this structure type, or if we're inside
      // of the structure type, then use a back reference to avoid infinite
      // recursion.
      if (ids.count(struct_ptr)) {
        ss << (alphanum ? "_M" : "%") << ids[struct_ptr];

      // We've not yet serialized this structure.
      } else {

        // Start by emitting a new structure ID for this structure and memoizing
        // it to prevent infinite recursion (e.g. on linked lists).
        ids[struct_ptr] = ids.size();
        ss << '=' << ids[struct_ptr] << (alphanum ? "_E" : "{");

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
          TranslateTypeInternal(*el_ty, ss, ids, dl, alphanum);
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
      TranslateTypeInternal(*vec_ptr->getElementType(), ss, ids, dl, alphanum);
      ss << 'x' << vec_ptr->getNumElements() << (alphanum ? "_H" : ">");
      break;
    }

    case llvm::Type::ArrayTyID: {
      const auto array_ptr = llvm::cast<llvm::ArrayType>(&type);
      ss << (alphanum ? "_C" : "[");
      TranslateTypeInternal(*array_ptr->getElementType(), ss, ids, dl,
                            alphanum);
      ss << 'x' << array_ptr->getNumElements() << (alphanum ? "_D" : "]");
      break;
    }

    case llvm::Type::PointerTyID: {
      ss << (alphanum ? "_S" : "*");
      auto derived = llvm::dyn_cast<llvm::PointerType>(&type);
      auto elem_type = derived->getElementType();

      // Get the type of the pointee.
      if (elem_type->isSized()) {
        TranslateTypeInternal(*elem_type, ss, ids, dl, alphanum);

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

}  // namespace

std::string TranslateType(llvm::Type &type, const llvm::DataLayout &dl,
                          bool alphanum) {
  std::stringstream ss;
  std::unordered_map<llvm::StructType *, size_t> ids = {};
  TranslateTypeInternal(type, ss, ids, dl, alphanum);
  return ss.str();
}

}  // namespace anvill
