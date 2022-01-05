/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Passes/ConvertSymbolicReturnAddressToConcreteReturnAddress.h>

#include <anvill/ABI.h>
#include <anvill/CrossReferenceFolder.h>
#include <anvill/CrossReferenceResolver.h>
#include <anvill/Utils.h>
#include <glog/logging.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/IRBuilder.h>

namespace anvill {

llvm::PreservedAnalyses
ConvertSymbolicReturnAddressToConcreteReturnAddress::run(
    llvm::Function &func, llvm::FunctionAnalysisManager &fam) {

  if (func.isDeclaration()) {
    return llvm::PreservedAnalyses::all();
  }

  llvm::Module *module = func.getParent();
  const llvm::DataLayout &dl = module->getDataLayout();

  NullCrossReferenceResolver resolver;
  CrossReferenceFolder folder(resolver, dl);

  std::vector<std::pair<llvm::Instruction *, llvm::Use *>> uses;

  auto get_ra_use = [&] (llvm::Use &use) -> llvm::Use * {
    if (auto used_ce = llvm::dyn_cast<llvm::ConstantExpr>(use.get())) {
      auto xr = folder.TryResolveReferenceWithCaching(used_ce);
      if (xr.references_return_address) {
        return &use;
      }
    }
    return nullptr;
  };

  for (llvm::Instruction &inst : llvm::instructions(func)) {
    for (llvm::Use &use : inst.operands()) {
      if (auto use_ptr = get_ra_use(use)) {
        uses.emplace_back(&inst, use_ptr);
      }
    }
  }

  if (uses.empty()) {
    return llvm::PreservedAnalyses::all();
  }

  auto is_pti_of_ra = [] (llvm::ConstantExpr *expr) -> bool {
    if (expr->getOpcode() == llvm::Instruction::PtrToInt) {
      auto base = llvm::dyn_cast<llvm::GlobalValue>(expr->getOperand(0u));
      return base && base->getName() == kSymbolicRAName;
    } else {
      return false;
    }
  };

  auto is_bc_of_ra = [] (llvm::ConstantExpr *expr) -> bool {
    if (expr->getOpcode() == llvm::Instruction::BitCast) {
      auto base = llvm::dyn_cast<llvm::GlobalValue>(expr->getOperand(0u));
      return base && base->getName() == kSymbolicRAName;
    } else {
      return false;
    }
  };

  llvm::LLVMContext &context = module->getContext();
  llvm::Function *ret_addr_func = llvm::Intrinsic::getDeclaration(
      module, llvm::Intrinsic::returnaddress);
  llvm::Value *args[] = {
      llvm::ConstantInt::get(llvm::Type::getInt32Ty(context), 0)};

  llvm::IRBuilder<> ir(context);
  ir.SetInsertPoint(&(func.getEntryBlock()),
                    func.getEntryBlock().getFirstInsertionPt());

  auto ra = ir.CreateCall(ret_addr_func->getFunctionType(),
                          ret_addr_func, args, "return_address");
  auto ce_insert_loc = ra->getNextNode();

  for (auto i = 0ul; i < uses.size(); ++i) {
    llvm::Instruction * const inst = uses[i].first;
    llvm::Use * const use = uses[i].second;
    llvm::ConstantExpr *ce = llvm::dyn_cast<llvm::ConstantExpr>(use->get());
    if (!ce) {
      continue;
    }

    llvm::Type * const ce_type = ce->getType();

    if (is_pti_of_ra(ce)) {
      auto pti = llvm::PtrToIntInst::Create(
          llvm::Instruction::PtrToInt, ra, ce_type);
      pti->insertAfter(ra);
      CopyMetadataTo(inst, pti);
      use->set(pti);

    } else if (is_bc_of_ra(ce)) {
      if (ce_type == ra->getType()) {
        CopyMetadataTo(inst, ra);
        use->set(ra);

      } else if (ce_type->isPointerTy()) {
        auto bc = llvm::BitCastInst::Create(
            llvm::Instruction::BitCast, ra, ce_type);
        bc->insertAfter(ra);
        CopyMetadataTo(inst, bc);

      } else if (ce_type->isIntegerTy()) {
        auto pti = llvm::PtrToIntInst::Create(
            llvm::Instruction::PtrToInt, ra, ce_type);
        pti->insertAfter(ra);
        CopyMetadataTo(inst, pti);
        use->set(pti);
      }

    } else {
      auto ce_inst = ce->getAsInstruction();
      ce_inst->insertBefore(ce_insert_loc);
      ce_insert_loc = ce_inst;

      CopyMetadataTo(inst, ce_inst);

      use->set(ce_inst);

      for (llvm::Use &op_use : ce_inst->operands()) {
        if (auto use_ptr = get_ra_use(op_use)) {
          uses.emplace_back(ce_inst, use_ptr);
        }
      }
    }
  }

  return llvm::PreservedAnalyses::none();
}

llvm::StringRef ConvertSymbolicReturnAddressToConcreteReturnAddress::name(void) {
  return "ConvertSymbolicReturnAddressToConcreteReturnAddress";
}

// Look for uses of the `(ptrtoint __remill_ra)` constant expression
// representing uses of the return address, and translate them to concrete uses
// of the return address.
void AddConvertSymbolicReturnAddressToConcreteReturnAddress(
    llvm::FunctionPassManager &fpm) {
  fpm.addPass(ConvertSymbolicReturnAddressToConcreteReturnAddress());
}

}  // namespace anvill
