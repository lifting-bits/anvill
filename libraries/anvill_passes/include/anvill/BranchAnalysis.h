#include <llvm/IR/Instructions.h>
#include <llvm/IR/ValueMap.h>
#include <llvm/Pass.h>

// Proven equivalent comparison
struct BranchResult {
  llvm::Value *lhs;
  llvm::Value *rhs;
  ComparisonOp;
};