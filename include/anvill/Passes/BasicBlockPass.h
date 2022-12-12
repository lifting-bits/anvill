#pragma once

#include <anvill/Utils.h>
#include <glog/logging.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>

#include <unordered_map>

#include "anvill/Declarations.h"

namespace anvill {


class BasicBlockContexts {
 public:
  virtual std::optional<std::reference_wrapper<const BasicBlockContext>>
  GetBasicBlockContextForAddr(uint64_t addr) const = 0;
};

template <class T>
class BasicBlockPass : public llvm::PassInfoMixin<BasicBlockPass<T>> {
 private:
  const BasicBlockContexts &contexts;


 public:
  static llvm::StringRef name(void) {
    return T::name();
  }

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM) {
    auto &bb_pass = *static_cast<T *>(this);
    auto bbaddr = anvill::GetBasicBlockAddr(&F);
    if (bbaddr.has_value()) {
      auto bb_cont = this->contexts.GetBasicBlockContextForAddr(*bbaddr);
      if (bb_cont) {
        return bb_pass.runOnBasicBlockFunction(F, AM, *bb_cont);
      }
    }

    return llvm::PreservedAnalyses::all();
  }

 protected:
  BasicBlockPass(const BasicBlockContexts &contexts) : contexts(contexts) {}
};
}  // namespace anvill