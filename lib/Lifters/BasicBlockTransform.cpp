#include "BasicBlockTransform.h"

#include <anvill/Declarations.h>
#include <anvill/Specification.h>
#include <anvill/Utils.h>
#include <glog/logging.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/ValueHandle.h>
#include <llvm/Support/Casting.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/ValueMapper.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Util.h>

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
  // TODO(Ian): instead of doing this allow StoreNative to take an insertion point that isnt a block end.
  auto cont_block =
      llvm::cast<llvm::BranchInst>(nfunc->getEntryBlock().getTerminator())
          ->getSuccessor(0);
  nfunc->getEntryBlock().getTerminator()->eraseFromParent();

  auto state_ptr = nfunc->getArg(remill::kStatePointerArgNum);

  auto mem_ptr_ref = remill::LoadMemoryPointerRef(&nfunc->getEntryBlock());
  auto mem_ptr_ty = nfunc->getArg(remill::kMemoryPointerArgNum)->getType();

  for (size_t i = 0; i < vars.size(); i++) {
    llvm::Value *native_val = nfunc->getArg(i + num_bb_func_pars);
    auto decl = vars[i];
    auto mem_ptr = ir.CreateLoad(mem_ptr_ty, mem_ptr_ref);
    auto new_mem =
        StoreNativeValue(native_val, decl, this->types, this->intrinsics,
                         ir.GetInsertBlock(), state_ptr, mem_ptr);
    ir.CreateStore(new_mem, mem_ptr_ref);
  }

  llvm::BranchInst::Create(cont_block, &nfunc->getEntryBlock());

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