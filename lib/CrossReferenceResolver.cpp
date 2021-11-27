/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/CrossReferenceResolver.h>

#include <glog/logging.h>

#include <anvill/Lifters.h>
#include <anvill/Providers.h>
#include <llvm/IR/IRBuilder.h>
#include <remill/BC/Util.h>

namespace anvill {

std::optional<std::uint64_t> NullCrossReferenceResolver::AddressOfEntity(
    llvm::Constant *ent) const {
  return std::nullopt;
}

llvm::Constant *NullCrossReferenceResolver::EntityAtAddress(
    std::uint64_t, llvm::Type *, unsigned) const {
  return nullptr;
}

class EntityCrossReferenceResolverImpl {
 public:
  EntityLifter entity_lifter;
  ValueLifter value_lifter;

  inline EntityCrossReferenceResolverImpl(const EntityLifter &entity_lifter_)
      : entity_lifter(entity_lifter_),
        value_lifter(entity_lifter) {}
};

EntityCrossReferenceResolver::~EntityCrossReferenceResolver(void) {}

EntityCrossReferenceResolver::EntityCrossReferenceResolver(
    const EntityLifter &entity_lifter_)
    : impl(new EntityCrossReferenceResolverImpl(entity_lifter_)) {}

std::optional<std::uint64_t> EntityCrossReferenceResolver::AddressOfEntity(
    llvm::Constant *ent) const {
  return impl->entity_lifter.AddressOfEntity(ent);
}

llvm::Constant *EntityCrossReferenceResolver::EntityAtAddress(
    std::uint64_t addr, llvm::Type *value_type, unsigned addr_space) const {

  llvm::Constant *ret = impl->value_lifter.Lift(
      addr, value_type, addr_space);
  if (ret && value_type) {
    auto ptr_type = llvm::PointerType::get(value_type, addr_space);
    auto ret_ptr_type = llvm::dyn_cast<llvm::PointerType>(ret->getType());
    CHECK_NOTNULL(ret_ptr_type);

    if (ret_ptr_type != ptr_type) {
      if (auto ret_addr_space = ret_ptr_type->getAddressSpace();
          ret_addr_space != addr_space) {
        return llvm::ConstantExpr::getAddrSpaceCast(
            llvm::ConstantExpr::getBitCast(
                ret, llvm::PointerType::get(value_type, ret_addr_space)),
            ptr_type);
      } else {
        return llvm::ConstantExpr::getBitCast(ret, ptr_type);
      }
    }
  }
  return ret;

//  auto &type_provider = entity_lifter.TypeProvider();
//
//  // Try to look it up as a function.
//  //
//  // NOTE(pag): We can't index into a function address.
//  if (std::optional<FunctionDecl> maybe_func_decl =
//          type_provider.TryGetFunctionType(addr);
//      maybe_func_decl) {
//    if (maybe_func_decl->address == addr) {
//      return entity_lifter.DeclareEntity(*maybe_func_decl);
//    }
//  }
//
//  llvm::Type *entity_type = nullptr;
//  llvm::Constant *entity = nullptr;
//  std::uint64_t entity_addr = addr;
//
//  if (std::optional<GlobalVarDecl> maybe_var_decl =
//                 type_provider.TryGetVariableType(addr)) {
//    entity_addr = maybe_var_decl->address;
//    entity_type = maybe_var_decl->type;
//    entity = entity_lifter.DeclareEntity(*maybe_var_decl);
//
//  // Try to see if it's one past the end of a known entity.
//  } else if (std::optional<GlobalVarDecl> maybe_prev_var_decl =
//                 type_provider.TryGetVariableType(addr - 1u);
//             maybe_prev_var_decl && addr) {
//
//    entity_addr = maybe_prev_var_decl->address;
//    entity_type = maybe_var_decl->type;
//    entity = entity_lifter.DeclareEntity(*maybe_prev_var_decl);
//  }
//
//  if (entity_addr == addr) {
//    return entity;  // NOTE(pag): Also covers the `!entity` case.
//  }
//
//  llvm::LLVMContext &context = entity->getContext();
//  llvm::IRBuilder<> ir(context);
//  llvm::PointerType *i8_ptr_ty = llvm::Type::getInt8PtrTy(context, 0);
//  llvm::IntegerType *index_ty = llvm::Type::getInt32Ty(context);
//
//  const llvm::DataLayout &dl = entity_lifter.DataLayout();
//  llvm::SmallVector<llvm::Value *, 8u> indexes;
//  auto goal_offset = addr - entity_addr;
//  auto [offset, val_type] = remill::BuildIndexes(
//      dl, entity_type, 0u, goal_offset, indexes);
//
//  // Great, indexed nicely into it, or beyond it.
//  entity = llvm::ConstantExpr::getGetElementPtr(entity_type, entity, indexes);
//  entity_type = llvm::Type::getInt8Ty(context);
//  goal_offset -= offset;
//
//  if (!goal_offset) {
//    return entity;
//  }
//
//  entity = llvm::ConstantExpr::getBitCast(
//      entity, llvm::PointerType::get(entity_type, 0));
//
//  return llvm::ConstantExpr::getGetElementPtr(
//      entity_type, entity, llvm::ConstantInt::get(index_ty, goal_offset));
}

}  // namespace anvill
