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

// Lift the pointer at address `ea` which is getting referenced by the
// variable at `loc_ea`. It checks the type and lift them as function
// or variable pointer
llvm::Constant *ValueLifter::GetPointer(uint64_t ea, llvm::Type *data_type,
                                        EntityLifterImpl &ent_lifter,
                                        uint64_t loc_ea) const {

  llvm::Constant *found_entity_at = nullptr;
  auto &func_lifter = ent_lifter.function_lifter;

  // `ea` can be null; lift it as zero initialized
  if (!ea) {
    return llvm::Constant::getNullValue(data_type);
  }

  ent_lifter.ForEachEntityAtAddress(
      ea, [&](llvm::Constant *gv) { found_entity_at = gv; });

  if (found_entity_at) {
    return llvm::ConstantExpr::getBitCast(found_entity_at, data_type);
  }

  const auto pointer_type = llvm::dyn_cast<llvm::PointerType>(data_type);
  const auto elm_type = pointer_type->getElementType();

  if (elm_type->getTypeID() == llvm::Type::FunctionTyID) {

    // Get the function at the given address; if it is missing from the spec
    // fallback to returning the address
    if (auto maybe_decl = ent_lifter.type_provider->TryGetFunctionType(ea);
        maybe_decl) {
      auto func = func_lifter.DeclareFunction(*maybe_decl);
      auto func_in_context =
          func_lifter.AddFunctionToContext(func, ea, ent_lifter);

      // Getting wrong function pointer type here. Check??
      return llvm::ConstantExpr::getBitCast(func_in_context, pointer_type);
    } else {
      LOG(ERROR) << "Failed to lift function pointer at " << std::hex << ea
                 << " referenced by variable at " << loc_ea << std::dec;
    }

  } else if (auto maybe_decl =
                 ent_lifter.type_provider->TryGetVariableType(ea, dl);
             maybe_decl) {

    // if the variable start address matches with ea
    if (maybe_decl->address == ea) {
      auto var =
          ent_lifter.data_lifter.GetOrDeclareData(*maybe_decl, ent_lifter);
      return llvm::ConstantExpr::getBitCast(var, data_type);
    } else {
      llvm::IRBuilder<> builder(options.module->getContext());
      auto enclosing_var =
          ent_lifter.data_lifter.GetOrDeclareData(*maybe_decl, ent_lifter);
      return llvm::dyn_cast<llvm::Constant>(remill::BuildPointerToOffset(
          builder, enclosing_var, ea - maybe_decl->address, pointer_type));
    }

  // ea could be just after the section for symbols e.g `__text_end`;
  // get variable decl for `ea - 1` and build pointers with the offset
  } else if (auto maybe_decl =
                 ent_lifter.type_provider->TryGetVariableType(ea - 1, dl);
             maybe_decl) {

    llvm::IRBuilder<> builder(options.module->getContext());
    auto enclosing_var =
        ent_lifter.data_lifter.GetOrDeclareData(*maybe_decl, ent_lifter);
    return llvm::dyn_cast<llvm::Constant>(remill::BuildPointerToOffset(
        builder, enclosing_var, ea - maybe_decl->address, pointer_type));
  }

  // failed to lift pointer at `ea`. lift it as integer value
  LOG(ERROR) << "Missing references to " << std::hex << ea
             << " for the variable at " << loc_ea << std::dec;

  llvm::APInt value(dl.getTypeAllocSize(pointer_type), ea);
  return llvm::Constant::getIntegerValue(pointer_type, value);
}

// Interpret `data` as the backing bytes to initialize an `llvm::Constant`
// of type `type_of_data`. This requires access to `ent_lifter` to be able
// to lift pointer types that will reference declared data/functions.
llvm::Constant *ValueLifter::Lift(std::string_view data, llvm::Type *type,
                                  EntityLifterImpl &ent_lifter,
                                  uint64_t loc_ea) const {

  switch (type->getTypeID()) {
    case llvm::Type::IntegerTyID: {
      const auto size = static_cast<uint64_t>(dl.getTypeAllocSize(type));
      auto val = ConsumeBytesAsInt(data, size);
      return llvm::ConstantInt::get(type, val);
    }

    case llvm::Type::PointerTyID: {

      // Get the address of pointer type and look for it into the entity map
      const auto pointer_type = llvm::dyn_cast<llvm::PointerType>(type);
      const auto size = dl.getTypeAllocSize(pointer_type);
      auto value = ConsumeBytesAsInt(data, size);
      auto address = value.getZExtValue();

      // decompiler may resolve the references of a pointer to itself.
      // e.g:
      // 00004008  void* __dso_handle = __dso_handle
      // If the references resolves to itself avoid lifting the pointer
      if (address == loc_ea) {
        return llvm::Constant::getIntegerValue(pointer_type, value);
      }

      return GetPointer(address, type, ent_lifter, loc_ea);
    } break;

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
        auto const_elm =
            Lift(data.substr(offset), elm_type, ent_lifter, loc_ea);
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
        auto const_elm =
            Lift(data.substr(elm_offset), elm_type, ent_lifter, loc_ea);
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
        auto const_elm =
            Lift(data.substr(elm_offset), elm_type, ent_lifter, loc_ea);
        initializer_list.push_back(const_elm);
      }
      return llvm::ConstantVector::get(initializer_list);
    }

    case llvm::Type::FloatTyID: {
      const auto size = static_cast<uint64_t>(dl.getTypeAllocSize(type));
      auto val = ConsumeBytesAsInt(data, size);
      return llvm::ConstantFP::get(type, val.bitsToFloat());
    }

    case llvm::Type::DoubleTyID: {
      const auto size = static_cast<uint64_t>(dl.getTypeAllocSize(type));
      auto val = ConsumeBytesAsInt(data, size);
      return llvm::ConstantFP::get(type, val.bitsToDouble());
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
