#pragma once

#include <anvill/IntrinsicPass.h>

namespace anvill {


const std::string kFlagIntrinsicPrefix("__remill_flag_computation");
const std::string kCompareInstrinsicPrefix("__remill_compare");


template <typename UserFunctionPass, typename Result>
class BranchHintPass : public IntrinsicPass<UserFunctionPass, Result> {
 public:
  bool isTargetInstrinsic(const llvm::CallInst *callinsn) {
    if (const auto *callee = callinsn->getCalledFunction()) {
      return callee->getName().startswith(kCompareInstrinsicPrefix);
    }

    return false;
  }
};
}  // namespace anvill
