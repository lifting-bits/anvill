/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "ValueLifter.h"

#include <anvill/ABI.h>
#include <anvill/Type.h>
#include <anvill/Utils.h>
#include <glog/logging.h>
#include <llvm/ADT/ArrayRef.h>
#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <remill/BC/Util.h>

#include "EntityLifter.h"

namespace anvill {

// Consume `num_bytes` of bytes from `data`, interpreting them as an integer,
// and update `data` in place, bumping out the first `num_bytes` of consumed
// data.
llvm::APInt ValueLifterImpl::ConsumeBytesAsInt(llvm::ArrayRef<uint8_t> &data,
                                               unsigned num_bytes) const {
  llvm::APInt result(num_bytes * 8u, 0u);
  for (auto i = 0u; i < num_bytes; ++i) {
    result <<= 8u;
    result |= static_cast<uint8_t>(data[i]);
  }
  data = data.drop_front(num_bytes);

  if (dl.isLittleEndian() && 1u < num_bytes) {
    return result.byteSwap();
  } else {
    return result;
  }
}

llvm::Constant *
ValueLifterImpl::GetFunctionPointer(const FunctionDecl &decl,
                                    EntityLifterImpl &ent_lifter) const {
  auto &func_lifter = ent_lifter.function_lifter;
  auto func = func_lifter.DeclareFunction(decl);
  auto func_in_context =
      func_lifter.AddFunctionToContext(func, decl, ent_lifter);
  return func_in_context;
}

llvm::Constant *
ValueLifterImpl::GetVarPointer(uint64_t var_ea, uint64_t search_ea,
                               EntityLifterImpl &ent_lifter,
                               llvm::Type *opt_elem_type) const {
  auto maybe_var =
      ent_lifter.type_provider->TryGetVariableType(search_ea, opt_elem_type);
  if (!maybe_var) {
    return nullptr;
  }

  llvm::PointerType *opt_ptr_type = llvm::PointerType::get(this->context, 0);

  // if the variable start address matches with ea
  if (maybe_var->address == var_ea) {
    return ent_lifter.data_lifter.GetOrDeclareData(*maybe_var, ent_lifter);

  } else {
    auto &context = options.module->getContext();
    llvm::IRBuilder<> builder(context);

    const auto enclosing_var =
        ent_lifter.data_lifter.GetOrDeclareData(*maybe_var, ent_lifter);

    return llvm::dyn_cast<llvm::Constant>(remill::BuildPointerToOffset(
        builder, enclosing_var, var_ea - maybe_var->address, opt_ptr_type));
  }
}

namespace {

// Sort of sketchy function to try to drill down on some referenced variable
// if we can.
static llvm::Constant *UnwrapZeroIndices(llvm::Constant *ret,
                                         llvm::Type *ret_type) {
  auto new_ret = ret;
  if (auto gep = llvm::dyn_cast<llvm::GEPOperator>(ret)) {
    if (gep->hasAllZeroIndices()) {
      new_ret = llvm::dyn_cast<llvm::Constant>(gep->getPointerOperand());
      if (new_ret != ret && new_ret->getType() == ret_type) {
        return new_ret;
      }
    }
  }

  new_ret = new_ret->stripPointerCasts();
  if (new_ret != ret && new_ret->getType() == ret_type) {
    return UnwrapZeroIndices(new_ret, ret_type);
  }

  new_ret =
      llvm::dyn_cast<llvm::Constant>(new_ret->stripPointerCastsAndAliases());
  if (new_ret != ret && new_ret->getType() == ret_type) {
    return UnwrapZeroIndices(new_ret, ret_type);
  }

  if (new_ret != ret) {
    new_ret = UnwrapZeroIndices(new_ret, ret_type);
  }

  if (new_ret != ret && new_ret->getType() == ret_type) {
    return new_ret;
  }

  return ret;
}

}  // namespace

// Lift pointers at `ea`.
//
// NOTE(pag): This returns `nullptr` upon failure to find `ea` as an
//            entity or plausible entity.
//
// NOTE(pag): `hinted_type` can be `nullptr`.
llvm::Constant *ValueLifterImpl::TryGetPointerForAddress(
    uint64_t ea, EntityLifterImpl &ent_lifter, llvm::Type *hinted_type) const {

  // First, try to see if we already have an entity for this address. Give
  // preference to an entity with a matching type. Then to global variables and
  // functions, then to aliases, then constants.
  llvm::Constant *found_entity_at = nullptr;
  ent_lifter.ForEachEntityAtAddress(ea, [&](llvm::Constant *gv) {
    if (llvm::isa<llvm::GlobalVariable>(gv) || llvm::isa<llvm::Function>(gv)) {
      found_entity_at = gv;
    } else if (!found_entity_at ||
               (llvm::isa<llvm::GlobalValue>(gv) &&
                !llvm::isa<llvm::GlobalValue>(found_entity_at))) {
      found_entity_at = gv;
    }
  });

  auto unwrap_zero_indices = [](llvm::Constant *ret) {
    const auto ret_type = ret->getType();
    return UnwrapZeroIndices(ret, ret_type);
  };

  // We've found the entity we wanted.
  if (found_entity_at) {
    return unwrap_zero_indices(found_entity_at);
  }

  auto maybe_decl = ent_lifter.type_provider->TryGetFunctionTypeOrDefault(ea);
  if (maybe_decl) {
    return GetFunctionPointer(*maybe_decl, ent_lifter);
  }

  // Try to create a `FunctionDecl` on-demand.
  if (hinted_type) {
    if (auto func_type = llvm::dyn_cast<llvm::FunctionType>(hinted_type)) {
      const auto func =
          llvm::Function::Create(func_type, llvm::GlobalValue::PrivateLinkage,
                                 ".anvill.value_lifter.temp", options.module);
      auto maybe_inv_decl = FunctionDecl::Create(*func, options.arch);
      func->eraseFromParent();
      if (maybe_inv_decl.Succeeded()) {
        auto inv_decl = maybe_inv_decl.TakeValue();
        inv_decl.address = ea;  // Force the address in.
        return GetFunctionPointer(inv_decl, ent_lifter);
      } else {
        LOG(ERROR) << "Cannot create function declaration for function at "
                   << std::hex << ea << std::dec << " with type "
                   << remill::LLVMThingToString(func_type) << ": "
                   << maybe_inv_decl.TakeError();
      }
    }
  }

  auto ret = GetVarPointer(ea, ea, ent_lifter, hinted_type);

  // `ea` could be just after the section for symbols e.g `__text_end`;
  // get variable decl for `ea - 1` and build pointers with the offset.
  if (!ret) {
    ret = GetVarPointer(ea, ea - 1u, ent_lifter, hinted_type);
  }

  return ret ? unwrap_zero_indices(ret) : nullptr;
}

// Lift the pointer at address `ea` which is getting referenced by the
// variable at `loc_ea`. It checks the type and lift them as function
// or variable pointer
llvm::Constant *ValueLifterImpl::GetPointer(uint64_t ea, llvm::Type *value_type,
                                            EntityLifterImpl &ent_lifter,
                                            uint64_t loc_ea,
                                            unsigned address_space) const {

  if (!value_type) {
    value_type = llvm::Type::getInt8Ty(context);
  }

  auto ptr_type = llvm::PointerType::get(context, address_space);
  auto ret = TryGetPointerForAddress(ea, ent_lifter, value_type);
  if (!ret) {
    if (!ea) {
      return llvm::Constant::getNullValue(ptr_type);

    } else {
      LOG_IF(WARNING, loc_ea)
          << "Failed to lift address " << std::hex << ea << " referenced by "
          << loc_ea << std::dec << " into a pointer of type "
          << remill::LLVMThingToString(ptr_type);

      LOG_IF(WARNING, !loc_ea)
          << "Failed to lift address " << std::hex << ea
          << " into a pointer of type " << remill::LLVMThingToString(ptr_type);

      return nullptr;
    }

  } else if (ret->getType()->getPointerAddressSpace() !=
             ptr_type->getAddressSpace()) {
    ret = llvm::ConstantExpr::getAddrSpaceCast(ret, ptr_type);
    ent_lifter.AddEntity(ret, ea);
  }

  return ret;
}

// Interpret `data` as the backing bytes to initialize an `llvm::Constant`
// of type `type_of_data`. This requires access to `ent_lifter` to be able
// to lift pointer types that will reference declared data/functions.
llvm::Constant *
ValueLifterImpl::Lift(llvm::ArrayRef<uint8_t> data, llvm::Type *type,
                      EntityLifterImpl &ent_lifter, uint64_t loc_ea) const {


  switch (type->getTypeID()) {

    // Read an integer. Sometimes the allocation size/padding will make us
    // overread, so we need to truncate.
    case llvm::Type::IntegerTyID: {
      const auto size = static_cast<uint64_t>(dl.getTypeAllocSize(type));
      auto val = ConsumeBytesAsInt(data, size);
      if (auto num_bits = type->getPrimitiveSizeInBits();
          num_bits < val.getBitWidth()) {
        return llvm::ConstantInt::get(type, val.trunc(num_bits));
      } else {
        return llvm::ConstantInt::get(type, val);
      }
    }

    // Get the address of pointer type and look for it into the entity map.
    case llvm::Type::PointerTyID: {
      const auto pointer_type = llvm::dyn_cast<llvm::PointerType>(type);
      const auto addr_space = pointer_type->getAddressSpace();
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

      // If we successfully lift it as a reference then we're in good shape.
      if (auto val =
              GetPointer(address, nullptr, ent_lifter, loc_ea, addr_space)) {
        return val;
      }

      // Otherwise, we do best-effort and cast the address.
      return llvm::Constant::getIntegerValue(pointer_type, value);

    } break;

    // Take apart the structure type, recursing into each element
    // so that we can create a constant structure.
    case llvm::Type::StructTyID: {
      const auto struct_type = llvm::dyn_cast<llvm::StructType>(type);
      const auto layout = dl.getStructLayout(struct_type);
      const auto num_elms = struct_type->getStructNumElements();
      std::vector<llvm::Constant *> initializer_list;
      initializer_list.reserve(num_elms);

      uint64_t prev_offset = 0;
      for (auto i = 0u; i < num_elms; ++i) {
        const auto elm_type = struct_type->getStructElementType(i);
        const auto offset = layout->getElementOffset(i);
        CHECK_LE(prev_offset, offset);
        auto const_elm = Lift(data.drop_front(offset), elm_type, ent_lifter,
                              loc_ea + offset);
        initializer_list.push_back(const_elm);
        prev_offset = offset;
      }
      return llvm::ConstantStruct::get(struct_type, initializer_list);
    }

    // Traverse through all the elements of array and create the initializer.
    case llvm::Type::ArrayTyID: {
      const auto array_type = llvm::dyn_cast<llvm::ArrayType>(type);
      const auto elm_type = type->getArrayElementType();
      const auto elm_size = dl.getTypeAllocSize(elm_type);
      const auto num_elms = type->getArrayNumElements();
      std::vector<llvm::Constant *> initializer_list;
      initializer_list.reserve(num_elms);

      for (auto i = 0u; i < num_elms; ++i) {
        const auto elm_offset = i * elm_size;
        auto const_elm = Lift(data.drop_front(elm_offset), elm_type, ent_lifter,
                              loc_ea + elm_offset);
        initializer_list.push_back(const_elm);
      }
      return llvm::ConstantArray::get(array_type, initializer_list);
    }

    // Traverse through all the elements of vector and create the initializer
    case llvm::Type::FixedVectorTyID: {
      const auto vec_type = llvm::dyn_cast<llvm::FixedVectorType>(type);
      const auto num_elms = vec_type->getNumElements();
      const auto elm_type = vec_type->getElementType();
      const auto elm_size = dl.getTypeAllocSize(elm_type);
      std::vector<llvm::Constant *> initializer_list;
      initializer_list.reserve(num_elms);

      for (auto i = 0u; i < num_elms; ++i) {
        const auto elm_offset = i * elm_size;
        auto const_elm = Lift(data.drop_front(elm_offset), elm_type, ent_lifter,
                              loc_ea + elm_offset);
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

    case llvm::Type::X86_FP80TyID: {
      const auto size = static_cast<uint64_t>(dl.getTypeStoreSize(type));
      auto val = ConsumeBytesAsInt(data, size);
      const llvm::APFloat float_val(llvm::APFloat::x87DoubleExtended(), val);
      return llvm::ConstantFP::get(type, float_val);
    }

    default:
      LOG(FATAL) << "Cannot initialize constant of unhandled LLVM type "
                 << remill::LLVMThingToString(type) << " at " << std::hex
                 << loc_ea << std::dec;

      return llvm::Constant::getNullValue(type);
  }
}

ValueLifterImpl::ValueLifterImpl(const LifterOptions &options_)
    : options(options_),
      dl(options.module->getDataLayout()),
      context(options.module->getContext()),
      type_specifier(options.TypeDictionary(), options.arch) {}

ValueLifter::~ValueLifter(void) {}

ValueLifter::ValueLifter(const EntityLifter &entity_lifter_)
    : impl(entity_lifter_.impl) {}

// Interpret `data` as the backing bytes to initialize an `llvm::Constant`
// of type `type_of_data`. `loc_ea`, if non-null, is the address at which
// `data` appears.
llvm::Constant *ValueLifter::Lift(llvm::ArrayRef<uint8_t> data,
                                  llvm::Type *type_of_data) const {
  return impl->value_lifter.Lift(data, type_of_data, *impl, 0);
}

// Interpret `ea` as being a pointer of type `pointer_type`.
//
// Returns an `llvm::Constant *` if the pointer is associated with a
// known or plausible entity, and a `nullptr` otherwise.
llvm::Constant *ValueLifter::Lift(uint64_t ea, llvm::Type *value_type,
                                  unsigned address_space) const {
  return impl->value_lifter.GetPointer(ea, value_type, *impl, address_space);
}

}  // namespace anvill
