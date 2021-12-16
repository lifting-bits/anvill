#pragma once

#include <llvm/IR/InstVisitor.h>

namespace anvill {

// Produces a complete linear defining slice, stopping when the slice becomes non linear (phi, non constant binop, load, argument)
// This slicer is expected to run after instcombiner.
// Return the value that is non linear (could be argument)

// If the expression is entirely constant then a constant will be returned as the stop value
class Slicer : public llvm::InstVisitor<Slicer, llvm::Value *> {
 private:
  llvm::SmallVector<llvm::Instruction *> resultingSlice;


  std::optional<llvm::PtrToIntInst *> getConstantCast(llvm::Value *v);

 public:
  llvm::Value *checkInstruction(llvm::Value *targetValue);
  llvm::SmallVector<llvm::Instruction *> getSlice();

  // default case is stop condition
  llvm::Value *visitInstruction(llvm::Instruction &I);


  llvm::Value *visitCastInst(llvm::CastInst &I);

  // same with unary ops
  llvm::Value *visitUnaryOperator(llvm::UnaryOperator &I);


  // if RHS is constant then continue, otherwise stop.
  llvm::Value *visitBinaryOperator(llvm::BinaryOperator &I);
};
}  // namespace anvill