#pragma once

#include <anvill/ABI.h>
#include <anvill/IntrinsicPass.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>

namespace anvill {

// NOTE(ian): Unfortunately pretty sure CRTP is the only way to do this without running into issues with pass IDs
template <typename UserFunctionPass, typename Result>
class IndirectJumpPass : public IntrinsicPass<UserFunctionPass, Result> {
 public:
  IndirectJumpPass(void) {}

  // NOTE(ian): The jump table analysis could also be targetted towards incomplete switch intrinsics.
  // It is always safe to run this analysis because the bounds on the index are conservative.
  // That being said if the intrinsic is truly incomplete when we attempt to lower the switch
  // there will be missing labels in the pcbinding mapping, therefore it is unlikely the switch lowering pass
  // should be run against the incomplete switches. Perhaps the best solution here is to run the jump table analysis
  // on its own against incomplete switches and allow it to call back into the lifter for more code.
  bool isTargetInstrinsic(const llvm::CallInst *callinsn) {
    if (const auto *callee = callinsn->getCalledFunction()) {
      return callee->getName().equals(kAnvillSwitchCompleteFunc);
    }

    return false;
  }


  Result runOnIntrinsic(llvm::CallInst *indirectJump,
                        llvm::FunctionAnalysisManager &am, Result agg) {
    auto &function_pass = *static_cast<UserFunctionPass *>(this);
    return function_pass.runOnIndirectJump(indirectJump, am, std::move(agg));
  }
};

}  // namespace anvill