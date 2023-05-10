#include <llvm/IR/PassManager.h>

// This pass collects additional stats which are useful for measuring code quality.


namespace anvill {
class CodeQualityStatCollector
    : public llvm::PassInfoMixin<CodeQualityStatCollector> {
 public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &analysisManager);

  static llvm::StringRef name(void);
};
}  // namespace anvill
