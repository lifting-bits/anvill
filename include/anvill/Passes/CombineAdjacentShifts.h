#include <llvm/IR/PassManager.h>

// Identify `(ashr (shl V, A), B)` and try to convert to
//
//        V_short = trunc V to iA
//        V_signed = sext V_short
//        res = shl V_signed, A - B
namespace anvill {
class CombineAdjacentShifts final
    : public llvm::PassInfoMixin<CombineAdjacentShifts> {
 public:
  static llvm::StringRef name(void);

  llvm::PreservedAnalyses run(llvm::Function &func,
                              llvm::FunctionAnalysisManager &fam);
};

}  // namespace anvill
