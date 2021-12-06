/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Lifters.h>

#include <anvill/ABI.h>
#include <anvill/Providers.h>
#include <anvill/Type.h>
#include <glog/logging.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Intrinsics.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/Util.h>

namespace anvill {

void LifterOptions::CheckModuleContextMatchesArch(void) const {
  CHECK_EQ(&(module->getContext()), arch->context);
}

// Return the data layout associated with the lifter options.
const llvm::DataLayout &LifterOptions::DataLayout(void) const {
  return module->getDataLayout();
}

// Dictionary of types to be used by the type specifier. Any time we load
// or store types into memory, we may be operating on wrapped types, e.g.
// a structure wrapping an `i32`, signalling that we're actually dealing with
// a signed integer. To know what is what, we need to know the dictionary of
// interpretable types.
const ::anvill::TypeDictionary &LifterOptions::TypeDictionary(void) const {
  return type_provider.Dictionary();
}

// Initialize the stack frame with a constant expression of the form:
//
//    (ptrtoint __anvill_sp)
llvm::Value *LifterOptions::SymbolicStackPointerInit(
    llvm::IRBuilderBase &ir, const remill::Register *sp_reg,
    uint64_t func_address) {

  auto &context = ir.getContext();
  auto block = ir.GetInsertBlock();
  auto module = block->getModule();

  auto type = remill::RecontextualizeType(sp_reg->type, context);

  auto base_sp = module->getGlobalVariable(kSymbolicSPName);
  if (!base_sp) {
    base_sp = new llvm::GlobalVariable(
        *module, type, false, llvm::GlobalValue::ExternalLinkage,
        llvm::Constant::getNullValue(type), kSymbolicSPName);
  }

  return llvm::ConstantExpr::getPtrToInt(base_sp, type);
}

// Initialize the program counter with a constant expression of the form:
//
//    (ptrtoint __anvill_pc)
llvm::Value *LifterOptions::SymbolicProgramCounterInit(
    llvm::IRBuilderBase &ir, const remill::Register *pc_reg,
    uint64_t func_address) {

  auto &context = ir.getContext();
  auto block = ir.GetInsertBlock();
  auto module = block->getModule();
  auto type = remill::RecontextualizeType(pc_reg->type, context);

  auto base_pc = module->getGlobalVariable(kSymbolicPCName);
  if (!base_pc) {
    base_pc = new llvm::GlobalVariable(
        *module, type, false, llvm::GlobalValue::ExternalLinkage,
        llvm::Constant::getNullValue(type), kSymbolicPCName);
  }

  return llvm::ConstantExpr::getAdd(
      llvm::ConstantExpr::getPtrToInt(base_pc, type),
      llvm::ConstantInt::get(type, func_address, false));
}

// Initialize the return address with a constant expression of the form:
//
//    (ptrtoint __anvill_ra)
llvm::Value *LifterOptions::SymbolicReturnAddressInit(
    llvm::IRBuilderBase &ir, llvm::IntegerType *type, uint64_t func_address) {
  auto &context = ir.getContext();
  auto block = ir.GetInsertBlock();
  auto module = block->getModule();
  type = llvm::dyn_cast<llvm::IntegerType>(
      remill::RecontextualizeType(type, context));
  auto base_ra = module->getGlobalVariable(kSymbolicRAName);
  if (!base_ra) {
    base_ra = new llvm::GlobalVariable(
        *module, type, false, llvm::GlobalValue::ExternalLinkage,
        llvm::Constant::getNullValue(type), kSymbolicRAName);
  }
  return llvm::ConstantExpr::getPtrToInt(base_ra, type);
}

// Initialize the return address with the result of:
//
//    call llvm.returnaddress()
llvm::Value *LifterOptions::ConcreteReturnAddressInit(
    llvm::IRBuilderBase &ir, llvm::IntegerType *type, uint64_t) {
  auto &context = ir.getContext();
  auto block = ir.GetInsertBlock();
  auto module = block->getModule();
  type = llvm::dyn_cast<llvm::IntegerType>(
      remill::RecontextualizeType(type, context));

  auto ret_addr_func = llvm::Intrinsic::getDeclaration(
      module, llvm::Intrinsic::returnaddress);
  llvm::Value *args[] = {
      llvm::ConstantInt::get(llvm::Type::getInt32Ty(context), 0)};

  return ir.CreatePtrToInt(
      ir.CreateCall(ret_addr_func->getFunctionType(), ret_addr_func, args),
      type);
}

}  // namespace anvill
