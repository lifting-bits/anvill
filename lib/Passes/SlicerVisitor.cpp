/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Passes/SlicerVisitor.h>

namespace anvill {
llvm::Value *Slicer::checkInstruction(llvm::Value *targetValue) {
  if (auto *insn = llvm::dyn_cast<llvm::Instruction>(targetValue)) {
    return this->visit(insn);
  }

  return targetValue;
}


llvm::SmallVector<llvm::Instruction *> Slicer::getSlice() {
  llvm::SmallVector<llvm::Instruction *> res;
  std::reverse_copy(this->resultingSlice.begin(), this->resultingSlice.end(),
                    std::back_inserter(res));
  return res;
}

// just assume we are non linear
llvm::Value *Slicer::visitInstruction(llvm::Instruction &I) {
  return &I;
}

llvm::Value *Slicer::visitCastInst(llvm::CastInst &I) {
  assert(I.getNumOperands() == 1);
  this->resultingSlice.push_back(&I);
  return this->checkInstruction(I.getOperand(0));
}


// same with unary ops
llvm::Value *Slicer::visitUnaryOperator(llvm::UnaryOperator &I) {
  assert(I.getNumOperands() == 1);
  this->resultingSlice.push_back(&I);
  return this->checkInstruction(I.getOperand(0));
}

// if RHS is constant then continue, otherwise stop.
llvm::Value *Slicer::visitBinaryOperator(llvm::BinaryOperator &I) {
  assert(I.getNumOperands() == 2);
  if (!llvm::isa<llvm::Constant>(I.getOperand(1))) {
    return &I;
  }

  this->resultingSlice.push_back(&I);
  return this->checkInstruction(I.getOperand(0));
}


}  // namespace anvill
