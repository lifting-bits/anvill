#pragma once
#include <anvill/BranchAnalysis.h>
#include <anvill/IntrinsicPass.h>

#include <map>
namespace anvill {
class SimplifyStackArithFlags
    : public IntrinsicPass<SimplifyStackArithFlags, llvm::PreservedAnalyses>,
      llvm::PassInfoMixin<SimplifyStackArithFlags> {


 private:
  // Flags that can be treated as a constant boolean
  std::map<ArithFlags, bool> constant_flags = {{ArithFlags::OF, false},
                                               {ArithFlags::ZF, false},
                                               {ArithFlags::SIGN, true}};

 public:
  SimplifyStackArithFlags(bool stack_pointer_is_signed) {
    this->constant_flags.insert({ArithFlags::SIGN, stack_pointer_is_signed});
  }

  llvm::PreservedAnalyses runOnIntrinsic(llvm::CallInst *indirectJump,
                                         llvm::FunctionAnalysisManager &am,
                                         llvm::PreservedAnalyses);


  static llvm::PreservedAnalyses INIT_RES;


  bool isTargetInstrinsic(const llvm::CallInst *callinsn);
  static llvm::StringRef name();
};

}  // namespace anvill