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
  GetBasicBlockContextForUid(Uid uid) const = 0;
  virtual const FunctionDecl &GetFunctionAtAddress(uint64_t addr) const = 0;
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
    auto bbuid = anvill::GetBasicBlockUid(&F);
    if (bbuid.has_value()) {
      auto maybe_bb_cont = contexts.GetBasicBlockContextForUid(*bbuid);
      if (maybe_bb_cont) {
        const BasicBlockContext &bb_cont = *maybe_bb_cont;
        auto &parent_func =
            contexts.GetFunctionAtAddress(bb_cont.GetParentFunctionAddress());
        return bb_pass.runOnBasicBlockFunction(F, AM, bb_cont, parent_func);
      }
    }

    return llvm::PreservedAnalyses::all();
  }

 protected:
  BasicBlockPass(const BasicBlockContexts &contexts) : contexts(contexts) {}
};
}  // namespace anvill