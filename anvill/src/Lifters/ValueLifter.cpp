/*
 * Copyright (c) 2021 Trail of Bits, Inc.
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

#include "ValueLifter.h"

#include <glog/logging.h>
#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <remill/BC/Compat/VectorType.h>
#include <remill/BC/Util.h>

#include "EntityLifter.h"

namespace anvill {

// Consume `num_bytes` of bytes from `data`, interpreting them as an integer,
// and update `data` in place, bumping out the first `num_bytes` of consumed
// data.
llvm::APInt ValueLifter::ConsumeBytesAsInt(std::string_view &data,
                                           unsigned num_bytes) const {
  llvm::APInt result(num_bytes * 8u, 0u);
  for (auto i = 0u; i < num_bytes; ++i) {
    result <<= 8u;
    result |= data[i];
  }
  data = data.substr(num_bytes);

  if (dl.isLittleEndian() && 1u < num_bytes) {
    return result.byteSwap();
  } else {
    return result;
  }
}

// Interpret `data` as the backing bytes to initialize an `llvm::Constant`
// of type `type_of_data`. This requires access to `ent_lifter` to be able
// to lift pointer types that will reference declared data/functions.
llvm::Constant *ValueLifter::Lift(std::string_view data, llvm::Type *type,
                                  EntityLifterImpl &ent_lifter) const {

  switch (type->getTypeID()) {
    case llvm::Type::IntegerTyID: {
      const auto size = static_cast<uint64_t>(dl.getTypeAllocSize(type));
      auto val = ConsumeBytesAsInt(data, size);
      return llvm::ConstantInt::get(type, val);
    }

    case llvm::Type::PointerTyID: {
      const auto pointer_type = llvm::dyn_cast<llvm::PointerType>(type);
      const auto size = dl.getTypeAllocSize(type);
      auto val = ConsumeBytesAsInt(data, size);
      return llvm::Constant::getIntegerValue(pointer_type, val);
    }

    case llvm::Type::StructTyID: {

      // Take apart the structure type, recursing into each element
      // so that we can create a constant structure
      const auto struct_type = llvm::dyn_cast<llvm::StructType>(type);
      const auto layout = dl.getStructLayout(struct_type);
      const auto num_elms = struct_type->getStructNumElements();
      std::vector<llvm::Constant *> initializer_list;
      initializer_list.reserve(num_elms);

      for (auto i = 0u; i < num_elms; ++i) {
        const auto elm_type = struct_type->getStructElementType(i);
        const auto offset = layout->getElementOffset(i);
        data = data.substr(offset);
        auto const_elm = Lift(data.substr(offset), elm_type, ent_lifter);
        initializer_list.push_back(const_elm);
      }
      return llvm::ConstantStruct::get(struct_type, initializer_list);
    }

    case llvm::Type::ArrayTyID: {

      // Traverse through all the elements of array and create the initializer
      const auto array_type = llvm::dyn_cast<llvm::ArrayType>(type);
      const auto elm_type = type->getArrayElementType();
      const auto elm_size = dl.getTypeAllocSize(elm_type);
      const auto num_elms = type->getArrayNumElements();
      std::vector<llvm::Constant *> initializer_list;
      initializer_list.reserve(num_elms);

      for (auto i = 0u; i < num_elms; ++i) {
        const auto elm_offset = i * elm_size;
        auto const_elm = Lift(data.substr(elm_offset), elm_type, ent_lifter);
        initializer_list.push_back(const_elm);
      }
      return llvm::ConstantArray::get(array_type, initializer_list);
    }

    case llvm::GetFixedVectorTypeId(): {
      const auto vec_type = llvm::dyn_cast<llvm::FixedVectorType>(type);
      const auto num_elms = vec_type->getNumElements();
      const auto elm_type = vec_type->getElementType();
      const auto elm_size = dl.getTypeAllocSize(elm_type);
      std::vector<llvm::Constant *> initializer_list;
      initializer_list.reserve(num_elms);

      for (auto i = 0u; i < num_elms; ++i) {
        const auto elm_offset = i * elm_size;
        auto const_elm = Lift(data.substr(elm_offset), elm_type, ent_lifter);
        initializer_list.push_back(const_elm);
      }
      return llvm::ConstantVector::get(initializer_list);
    }

    default:
      LOG(ERROR) << "Unhandled LLVM Type: " << remill::LLVMThingToString(type);
      return llvm::Constant::getNullValue(type);
  }
}

ValueLifter::ValueLifter(const LifterOptions &options_)
    : options(options_),
      dl(options.module->getDataLayout()),
      context(options.module->getContext()) {}

}  // namespace anvill
