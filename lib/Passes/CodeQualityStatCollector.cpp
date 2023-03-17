
#define DEBUG_TYPE "code_quality"

#include <anvill/ABI.h>
#include <anvill/Passes/CodeQualityStatCollector.h>
#include <llvm/ADT/Statistic.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PassManager.h>

namespace anvill {
ALWAYS_ENABLED_STATISTIC(
    ConditionalComplexity,
    "A factor that approximates the complexity of the condition in branch instructions");
ALWAYS_ENABLED_STATISTIC(NumberOfInstructions, "Total number of instructions");
ALWAYS_ENABLED_STATISTIC(AbruptControlFlow, "Indirect control flow instructions");
ALWAYS_ENABLED_STATISTIC(IntToPointerCasts, "Integer to pointer casts");
ALWAYS_ENABLED_STATISTIC(PointerToIntCasts, "Pointer to integer casts");
ALWAYS_ENABLED_STATISTIC(AnvillStackPointers, "Anvill stack pointer");


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
        ++ConditionalComplexity;
        this->tryVisit(I.getOperand(0));
        this->tryVisit(I.getOperand(1));
      }
    }
  }

  void visitCmpInst(llvm::CmpInst &I) {
    ++ConditionalComplexity;
  }

  void visitUnaryOperator(llvm::UnaryOperator &I) {
    if (auto *inttype = llvm::dyn_cast<llvm::IntegerType>(I.getType())) {
      ++ConditionalComplexity;
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
    if (auto *int_to_ptr = llvm::dyn_cast<llvm::IntToPtrInst>(&i)) {
      ++IntToPointerCasts;
    }

    if (auto *int_to_ptr = llvm::dyn_cast<llvm::PtrToIntInst>(&i)) {
      ++PointerToIntCasts;
    }

    if (auto *store_inst = llvm::dyn_cast<llvm::StoreInst>(&i)) {
      if (store_inst->getPointerOperand()->getName() == kSymbolicSPName) {
        ++AnvillStackPointers;
      }
    }

    if (auto *load_inst = llvm::dyn_cast<llvm::LoadInst>(&i)) {
      if (load_inst->getPointerOperand()->getName() == kSymbolicSPName) {
        ++AnvillStackPointers;
      }
    }

    ++NumberOfInstructions;
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
          ++AbruptControlFlow;
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
