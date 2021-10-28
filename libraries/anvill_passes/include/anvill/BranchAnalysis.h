#include <anvill/ABI.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/ValueMap.h>
#include <llvm/Pass.h>

namespace anvill {
// Proven equivalent comparison
struct BranchResult {
  llvm::Value *lhs;
  llvm::Value *rhs;
};


extern const std::string kFlagIntrinsicPrefix;
extern const std::string kCompareInstrinsicPrefix;

// newtype of Predicate
struct RemillComparison {
  llvm::CmpInst::Predicate pred;
};

RemillComparison ParseComparisonIntrinsic(llvm::StringRef intrinsic_name);

class BranchAnalysis : public llvm::AnalysisInfoMixin<BranchAnalysis> {
 private:
  friend llvm::AnalysisInfoMixin<BranchAnalysis>;
  static llvm::AnalysisKey Key;


 private:
  std::optional<BranchResult> analyzeComparison(llvm::CallInst *intrinsic_call);

 public:
  BranchAnalysis() {}


  // Maps CallInst to anvill_compare prims to the result
  using Result = llvm::DenseMap<llvm::CallInst *, BranchResult>;

  Result run(llvm::Function &F, llvm::FunctionAnalysisManager &am);

  static llvm::StringRef name();
};
}  // namespace anvill