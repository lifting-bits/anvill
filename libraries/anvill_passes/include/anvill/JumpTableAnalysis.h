#pragma once

#include <anvill/IndirectJumpPass.h>
#include <anvill/SliceInterpreter.h>
#include <anvill/SliceManager.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/ValueMap.h>
#include <llvm/Pass.h>

namespace anvill {

enum CastType { ZEXT, SEXT, NONE };
struct Cast {
  CastType caTy;
  unsigned int toBits;

  llvm::APInt apply(llvm::APInt target) {
    switch (this->caTy) {
      case CastType::ZEXT: return target.zext(this->toBits);
      case CastType::SEXT: return target.sext(this->toBits);
      case CastType::NONE: return target;
    }
  }
};

// A slice that represents the computation of the program counter, given a loaded value from a jump table.
// The slice has one unknown argument which is the loaded value. The slice argument and return value are integers.
class PcRel {
 private:
  SliceID slice;

 public:
  PcRel(SliceID slice) : slice(slice) {}

  // Interprets the slice, providing loadedVal as the argument.
  llvm::APInt apply(SliceInterpreter &interp, llvm::APInt loadedVal);


  llvm::IntegerType *getExpectedType(SliceManager &);
};

// A slice that represents the computation from an index (some non-constant value) to a loaded address.
// The slice is linear and constant except for the index, resulting in one integer argument for the slice.`
class IndexRel {
 private:
  SliceID slice;
  llvm::Value *index;

 public:
  llvm::Value *getIndex();

  // Interprets the slice, substituting indexValue for the index, retrieving a jump table address.
  llvm::APInt apply(SliceInterpreter &interp, llvm::APInt indexValue);

  IndexRel(SliceID slice, llvm::Value *index) : slice(slice), index(index) {}
};

struct Bound {
  llvm::APInt lower;
  llvm::APInt upper;
  bool isSigned;

  bool lessThanOrEqual(llvm::APInt lhs, llvm::APInt rhs) {
    if (isSigned) {
      return lhs.sle(rhs);
    } else {
      return lhs.ule(rhs);
    }
  }
};

struct JumpTableResult {
  PcRel pcRel;
  IndexRel indexRel;
  Bound bounds;
  llvm::BasicBlock *defaultOut;
};

class JumpTableAnalysis : public IndirectJumpPass<JumpTableAnalysis> {

 private:
  SliceManager &slices;
  llvm::ValueMap<llvm::CallInst *, JumpTableResult> results;

 public:
  JumpTableAnalysis(SliceManager &slices)
      : IndirectJumpPass(),
        slices(slices) {}

  llvm::StringRef getPassName() const override;

  void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;
  bool runOnIndirectJump(llvm::CallInst *indirectJump);

  std::optional<JumpTableResult>
  getResultFor(llvm::CallInst *indirectJump) const;

  const llvm::ValueMap<llvm::CallInst *, JumpTableResult> &
  getAllResults() const {
    return this->results;
  }
};
}  // namespace anvill
