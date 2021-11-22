#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>

namespace anvill {

// Finds values in the form of:
//
//      %cmp = icmp eq val1, val2
//      %n = xor %cmp, 1
//
//      %br %cmp, d1, d2      (optional)
//
// and converts it to:
//
//      %cmp = icmp ne val1, val2
//      %n = %cmp
//      %br %cmp, d2, d1
//
// This happens often enough in lifted code due to bit shift ops, and the code
// with xors is more difficult to analyze and for a human to read. This pass
// should only work on boolean values, and handle when those are used in
// branches and selects.
class ConvertXorToCmp final : llvm::PassInfoMixin<ConvertXorToCmp> {
 public:
  ConvertXorToCmp(void) {}


  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static llvm::StringRef name(void);
};
}  // namespace anvill
