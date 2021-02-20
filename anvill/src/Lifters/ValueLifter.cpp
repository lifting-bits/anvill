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
#include <llvm/IR/Module.h>

#include <remill/BC/Util.h>
#include <remill/BC/Compat/VectorType.h>

namespace anvill {

// Consume `num_bytes` of bytes from `data`, and update `data` in place.
llvm::APInt ValueLifterImpl::ConsumeValue(std::string_view &data,
                                          unsigned num_bytes) {
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

llvm::Constant *ValueLifterImpl::Lift(
    std::string_view data, llvm::Type *type, const EntityLifter &ent_lifter) {

  const auto &dl = module.getDataLayout();
  switch (type->getTypeID()) {
    case llvm::Type::IntegerTyID: {
      const auto size = static_cast<uint64_t>(dl.getTypeAllocSize(type));
      auto val = ConsumeValue(data, size);
      return llvm::ConstantInt::get(type, val);
    }

    case llvm::Type::PointerTyID: {
      const auto pointer_type = llvm::dyn_cast<llvm::PointerType>(type);
      const auto size = dl.getTypeAllocSize(type);
      auto val = ConsumeValue(data, size);
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

ValueLifter::ValueLifter(llvm::Module &module_)
    : impl(std::make_shared<ValueLifterImpl>(module_)) {}

ValueLifterImpl::ValueLifterImpl(llvm::Module &module_)
    : module(module_),
      dl(module.getDataLayout()) {}

ValueLifter::~ValueLifter(void) {}

llvm::Constant *ValueLifter::Lift(
    std::string_view data, llvm::Type *type_of_data,
    const EntityLifter &entity_lifter) const {
  return impl->Lift(data, type_of_data, entity_lifter);
}

}  // namespace anvill
