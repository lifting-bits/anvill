#include <anvill/CrossReferenceResolver.h>
#include <anvill/Passes/RemoveCallIntrinsics.h>
#include <glog/logging.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/raw_ostream.h>
#include <remill/BC/Util.h>

#include "anvill/Utils.h"

namespace anvill {
llvm::StringRef RemoveCallIntrinsics::name(void) {
  return "Remove call intrinsics.";
}


namespace {}

llvm::PreservedAnalyses
RemoveCallIntrinsics::runOnIntrinsic(llvm::CallInst *remillFunctionCall,
                                     llvm::FunctionAnalysisManager &am,
                                     llvm::PreservedAnalyses prev) {
  CHECK(remillFunctionCall->getNumOperands() == 4);
  auto target_func = remillFunctionCall->getArgOperand(1);
  auto state_ptr = remillFunctionCall->getArgOperand(0);
  auto mem_ptr = remillFunctionCall->getArgOperand(2);

  CrossReferenceFolder xref_folder(
      this->xref_resolver,
      remillFunctionCall->getFunction()->getParent()->getDataLayout());
  auto ra = xref_folder.TryResolveReferenceWithClearedCache(target_func);
  auto f = remillFunctionCall->getFunction();
  DCHECK(!llvm::verifyFunction(*f, &llvm::errs()));

  if (ra.references_entity ||  // Related to an existing lifted entity.
      ra.references_global_value ||  // Related to a global var/func.
      ra.references_program_counter) {  // Related to `__anvill_pc`.

    std::shared_ptr<const CallableDecl> callable_decl =
        spec.FunctionAt(ra.u.address);

    if (auto pc_val =
            GetMetadata(lifter.Options().pc_metadata_name, *remillFunctionCall);
        pc_val.has_value()) {
      if (auto bb_addr = GetBasicBlockAddr(f); bb_addr.has_value()) {
        auto block_contexts = spec.GetBlockContexts();
        if (auto bb_ctx_ref =
                block_contexts.GetBasicBlockContextForAddr(*bb_addr);
            bb_ctx_ref.has_value()) {
          const auto &bb_ctx = bb_ctx_ref->get();
          auto func = bb_ctx.GetParentFunctionAddress();
          if (auto override_decl = spec.CallSiteAt({func, *pc_val})) {
            DLOG(INFO) << "Overriding call site at " << std::hex << *pc_val
                       << " in " << std::hex << func;
            callable_decl = override_decl;
          }
        }
      }
    }

    auto *entity = this->xref_resolver.EntityAtAddress(ra.u.address);
    if (callable_decl && entity) {
      llvm::IRBuilder<> ir(remillFunctionCall->getParent());
      ir.SetInsertPoint(remillFunctionCall);


      const remill::IntrinsicTable table(f->getParent());
      DLOG(INFO) << "Replacing call from: "
                 << remill::LLVMThingToString(remillFunctionCall)
                 << " with call to " << std::hex << ra.u.address
                 << " d has: " << std::string(entity->getName());
      auto *new_mem = callable_decl->CallFromLiftedBlock(
          entity, lifter.Options().TypeDictionary(), table, ir, state_ptr,
          mem_ptr);

      remillFunctionCall->replaceAllUsesWith(new_mem);
      remillFunctionCall->eraseFromParent();
      prev.intersect(llvm::PreservedAnalyses::none());
    }
  }

  DCHECK(!llvm::verifyFunction(*f, &llvm::errs()));

  return prev;
}


llvm::PreservedAnalyses RemoveCallIntrinsics::INIT_RES =
    llvm::PreservedAnalyses::all();


bool RemoveCallIntrinsics::isTargetInstrinsic(const llvm::CallInst *callinsn) {
  return callinsn->getCalledFunction() != nullptr &&
         callinsn->getCalledFunction()->getName().startswith(
             "__remill_function_call");
}
}  // namespace anvill
