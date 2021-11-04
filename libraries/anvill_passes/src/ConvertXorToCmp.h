#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>

namespace anvill {

class ConvertXorToCmp final : llvm::PassInfoMixin<ConvertXorToCmp> {
 public:
  ConvertXorToCmp(void) {}


  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static llvm::StringRef name(void);
};
}  // namespace anvill
