
#define DEBUG_TYPE "code_quality"

#include <anvill/ABI.h>
#include <anvill/CodeQualityStatCollector.h>
#include <llvm/ADT/Statistic.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PassManager.h>

namespace anvill {
STATISTIC(
    ConditionalComplexity,
    "A factor that approximates the complexity of the condition in branch instructions");
STATISTIC(NumberOfInstructions, "Total number of instructions");
STATISTIC(AbruptControlFlow, "Indirect control flow instructions");


namespace {
// The idea here is that we count the number of boolean expressions involved in this branch which should be an indicator of its complexity
class ConditionalComplexityVisitor
    : public llvm::InstVisitor<ConditionalComplexityVisitor> {

 public:
  void tryVisit(llvm::Value *v) {
    if (auto *insn = llvm::dyn_cast<llvm::Instruction>(v)) {
      this->visit(insn);
    }
  }

  void visitBinaryOperator(llvm::BinaryOperator &I) {
    if (auto *inttype = llvm::dyn_cast<llvm::IntegerType>(I.getType())) {
      if (inttype->getBitWidth() == 1) {
        ConditionalComplexity++;
        this->tryVisit(I.getOperand(0));
        this->tryVisit(I.getOperand(1));
      }
    }
  }

  void visitCmpInst(llvm::CmpInst &I) {
    ConditionalComplexity++;
  }

  void visitUnaryOperator(llvm::UnaryOperator &I) {
    if (auto *inttype = llvm::dyn_cast<llvm::IntegerType>(I.getType())) {
      ConditionalComplexity++;
      this->tryVisit(I.getOperand(0));
    }
  }
};
}  // namespace


llvm::PreservedAnalyses
CodeQualityStatCollector::run(llvm::Function &function,
                              llvm::FunctionAnalysisManager &analysisManager) {
  ConditionalComplexityVisitor complexity_visitor;
  for (auto &i : llvm::instructions(function)) {
    NumberOfInstructions++;
    if (auto *branch = llvm::dyn_cast<llvm::BranchInst>(&i)) {
      if (branch->isConditional()) {
        complexity_visitor.tryVisit(branch->getCondition());
      }
    }

    if (auto *cb = llvm::dyn_cast<llvm::CallBase>(&i)) {
      auto target = cb->getCalledFunction();
      if (target != nullptr) {
        if (target->getName() == kAnvillSwitchCompleteFunc ||
            target->getName() == kAnvillSwitchIncompleteFunc) {
          AbruptControlFlow++;
        }
      }
    }
  }
  return llvm::PreservedAnalyses::all();
}

llvm::StringRef CodeQualityStatCollector::name(void) {
  return "CodeQualityStatCollector";
}

}  // namespace anvill