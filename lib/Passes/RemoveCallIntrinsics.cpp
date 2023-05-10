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
  // remillFunctionCall->getFunction()->dump();
  // if (remillFunctionCall->getFunction()->getName().endswith(
  //         "basic_block_func4201200")) {
  //   LOG(FATAL) << "done";
  // }
  CHECK(remillFunctionCall->getNumOperands() == 4);
  auto target_func = remillFunctionCall->getArgOperand(1);
  auto state_ptr = remillFunctionCall->getArgOperand(0);
  auto mem_ptr = remillFunctionCall->getArgOperand(2);

  CrossReferenceFolder xref_folder(
      this->xref_resolver,
      remillFunctionCall->getFunction()->getParent()->getDataLayout());
  auto ra = xref_folder.TryResolveReferenceWithClearedCache(target_func);
  auto f = remillFunctionCall->getFunction();
  CHECK(!llvm::verifyFunction(*f, &llvm::errs()));

  if (ra.references_entity ||  // Related to an existing lifted entity.
      ra.references_global_value ||  // Related to a global var/func.
      ra.references_program_counter) {  // Related to `__anvill_pc`.

    // TODO(Ian): ignoring callsite decls for now
    auto fdecl = spec.FunctionAt(ra.u.address);
    auto entity = this->xref_resolver.EntityAtAddress(ra.u.address);
    if (fdecl && entity) {
      llvm::IRBuilder<> ir(remillFunctionCall->getParent());
      ir.SetInsertPoint(remillFunctionCall);


      const remill::IntrinsicTable table(
          remillFunctionCall->getFunction()->getParent());
      DLOG(INFO) << "Replacing call from: "
                 << remill::LLVMThingToString(remillFunctionCall)
                 << " with call to " << std::hex << ra.u.address
                 << " d has: " << std::string(entity->getName());
      auto new_mem =
          fdecl->CallFromLiftedBlock(entity, lifter.Options().TypeDictionary(),
                                     table, ir, state_ptr, mem_ptr);

      remillFunctionCall->replaceAllUsesWith(new_mem);
      remillFunctionCall->eraseFromParent();
      prev.intersect(llvm::PreservedAnalyses::none());
    }
  }

  CHECK(!llvm::verifyFunction(*f, &llvm::errs()));

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
