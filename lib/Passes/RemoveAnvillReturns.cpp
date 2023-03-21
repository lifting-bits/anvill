
#include <anvill/ABI.h>
#include <anvill/Passes/RemoveAnvillReturns.h>
#include <glog/logging.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>
#include <llvm/Support/Casting.h>
#include <remill/BC/Util.h>

#include <optional>
#include <tuple>
#include <vector>

#include "Utils.h"

namespace anvill {
llvm::StringRef RemoveAnvillReturns::name(void) {
  return "Remove anvill returns";
}

llvm::PreservedAnalyses
RemoveAnvillReturns::run(llvm::Function &F, llvm::FunctionAnalysisManager &AM) {
  auto intrinsic = F.getParent()->getFunction(anvill::kAnvillBasicBlockReturn);
  bool changed = false;

  if (intrinsic) {
    std::vector<llvm::CallInst *> calls;
    for (auto &insn : llvm::instructions(&F)) {
      if (auto cc = llvm::dyn_cast<llvm::CallInst>(&insn)) {
        if (cc->getCalledFunction() == intrinsic) {
          calls.push_back(cc);
        }
      }
    }

    for (auto cc : calls) {
      // either it's a void return with no args or there is 1 arg that is the type of the return
      if ((F.getReturnType()->isVoidTy() && cc->arg_size() == 0) ||
          (cc->arg_size() == 1 &&
           F.getReturnType() == cc->getArgOperand(0)->getType())) {
        changed = true;
        auto to_block = cc->getParent()->getTerminator();
        // block must be wellformed
        CHECK(to_block);
        to_block->eraseFromParent();


        if (F.getReturnType()->isVoidTy()) {
          llvm::ReturnInst::Create(F.getContext(), cc->getParent());
        } else {
          llvm::ReturnInst::Create(F.getContext(), cc->getArgOperand(0),
                                   cc->getParent());
        }

        cc->eraseFromParent();
      } else {

        LOG_IF(ERROR, cc->arg_size() == 1)
            << "Ret ty: " << remill::LLVMThingToString(F.getReturnType())
            << " arg mismatch: "
            << remill::LLVMThingToString(cc->getArgOperand(0)->getType());
        LOG_IF(ERROR, cc->arg_size() == 0)
            << "Expected void type for function with type: "
            << remill::LLVMThingToString(F.getReturnType());
      }
    }
  }

  return changed ? llvm::PreservedAnalyses::none()
                 : llvm::PreservedAnalyses::all();
}
}  // namespace anvill