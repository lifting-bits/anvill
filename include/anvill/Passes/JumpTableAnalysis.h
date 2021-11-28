/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <anvill/Passes/IndirectJumpPass.h>
#include <anvill/Passes/SliceInterpreter.h>
#include <anvill/Passes/SliceManager.h>
#include <llvm/ADT/DenseMap.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PassManager.h>
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

// A slice that represents the computation from an index (some non-constant
// value) to a loaded address. The slice is linear and constant except for the
// index, resulting in one integer argument for the slice.
class IndexRel {
 private:
  SliceID slice;
  llvm::Value *index;

 public:
  llvm::Value *getIndex();

  // Interprets the slice, substituting indexValue for the index, retrieving a
  // jump table address.
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

class JumpTableAnalysis
    : public IndirectJumpPass<
          JumpTableAnalysis, llvm::DenseMap<llvm::CallInst *, JumpTableResult>>,
      public llvm::AnalysisInfoMixin<JumpTableAnalysis> {

 private:
  friend llvm::AnalysisInfoMixin<JumpTableAnalysis>;
  static llvm::AnalysisKey Key;
  SliceManager &slices;

 public:
  JumpTableAnalysis(SliceManager &slices)
      : IndirectJumpPass(),
        slices(slices) {}

  static llvm::StringRef name(void);

  using Result = llvm::DenseMap<llvm::CallInst *, JumpTableResult>;

  static Result INIT_RES;

  Result runOnIndirectJump(llvm::CallInst *indirectJump,
                           llvm::FunctionAnalysisManager &am, Result agg);
};
}  // namespace anvill
