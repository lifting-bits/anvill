#pragma once

#include <anvill/ABI.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>

namespace anvill {

template <typename UserFunctionPass, typename Result>
class IntrinsicPass {

 private:
  std::vector<llvm::CallInst *> getTargetCalls(llvm::Function &fromFunction) {
    auto &function_pass = *static_cast<UserFunctionPass *>(this);
    std::vector<llvm::CallInst *> calls;
    for (auto &insn : llvm::instructions(fromFunction)) {
      llvm::Instruction *new_insn = &insn;
      if (llvm::CallInst *call_insn =
              llvm::dyn_cast<llvm::CallInst>(new_insn)) {
        if (function_pass.isTargetInstrinsic(call_insn)) {
          calls.push_back(call_insn);
        }
      }
    }
    return calls;
  }

 public:
  IntrinsicPass(void) {}

  Result run(llvm::Function &F, llvm::FunctionAnalysisManager &am);
};


template <typename UserFunctionPass, typename Result>
Result IntrinsicPass<UserFunctionPass, Result>::run(
    llvm::Function &F, llvm::FunctionAnalysisManager &am) {
  auto &function_pass = *static_cast<UserFunctionPass *>(this);
  Result total = function_pass.INIT_RES;
  for (auto targetCall : this->getTargetCalls(F)) {
    total = function_pass.runOnIntrinsic(targetCall, am, std::move(total));
  }

  return total;
}
}  // namespace anvill