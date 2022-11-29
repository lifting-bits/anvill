#include "BasicBlockTransform.h"

#include <anvill/Declarations.h>
#include <anvill/Specification.h>
#include <anvill/Utils.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/ValueHandle.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/ValueMapper.h>
#include <remill/BC/ABI.h>

#include "anvill/ABI.h"
#include "anvill/Lifters.h"

namespace anvill {
Transformed
CallAndInitializeParameters::TransformInternal(const AnvillBasicBlock &bb) {
  std::vector<llvm::Type *> args(
      bb.basic_block_repr_func->getFunctionType()->param_begin(),
      bb.basic_block_repr_func->getFunctionType()->param_end());


  auto num_bb_func_pars = args.size();
  auto vars = bb.context.GetAvailableVariables();
  for (const auto &v : vars) {
    args.push_back(v.type);
  }

  auto ntype = llvm::FunctionType::get(
      bb.basic_block_repr_func->getReturnType(), args, false);

  auto nfunc = llvm::Function::Create(ntype, llvm::GlobalValue::ExternalLinkage,
                                      bb.basic_block_repr_func->getName(),
                                      bb.basic_block_repr_func->getParent());


  llvm::ValueToValueMapTy mp;

  for (size_t i = 0;
       i < bb.basic_block_repr_func->getFunctionType()->getNumParams(); i++) {
    mp.insert({bb.basic_block_repr_func->getArg(i), nfunc->getArg(i)});
  }

  llvm::SmallVector<llvm::ReturnInst *, 10> rets;
  llvm::CloneFunctionInto(nfunc, bb.basic_block_repr_func, mp,
                          llvm::CloneFunctionChangeType::LocalChangesOnly,
                          rets);

  llvm::IRBuilder<> ir(&nfunc->getEntryBlock());

  llvm::Value *mem_ptr = nfunc->getArg(remill::kMemoryPointerArgNum);
  auto state_ptr = nfunc->getArg(remill::kStatePointerArgNum);


  llvm::GlobalVariable *dummy = new llvm::GlobalVariable(
      *bb.basic_block_repr_func->getParent(), mem_ptr->getType(), false,
      llvm::GlobalValue::ExternalLinkage, nullptr, "");

  mem_ptr->replaceAllUsesWith(dummy);

  for (size_t i = 0; i < vars.size(); i++) {
    llvm::Value *native_val = nfunc->getArg(i + num_bb_func_pars);
    auto decl = vars[i];
    mem_ptr = StoreNativeValue(native_val, decl, this->types, this->intrinsics,
                               ir.GetInsertBlock(), state_ptr, mem_ptr);
  }

  dummy->replaceAllUsesWith(mem_ptr);
  dummy->eraseFromParent();


  return {nfunc, vars};
}

Transformed BasicBlockTransform::Transform(const AnvillBasicBlock &bb) {
  auto res = this->TransformInternal(bb);
  res.new_func->setMetadata(
      kBasicBlockMetadata,
      bb.basic_block_repr_func->getMetadata(kBasicBlockMetadata));
  return res;
}


}  // namespace anvill