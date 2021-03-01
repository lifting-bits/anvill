#ifndef __POINTER_LIFTER
#define __POINTER_LIFTER

#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/Instruction.h>
#include <remill/BC/Util.h>

#include <algorithm>
#include <unordered_map>
#include <unordered_set>


namespace anvill {

class PointerLifter : public llvm::InstVisitor<PointerLifter, std::pair<llvm::Value *, bool>> {
 public:
  PointerLifter(llvm::Module &mod) : module(mod) {}

  // ReplaceAllUses - swaps uses of LLVM inst with other LLVM inst
  // Adds users to the next worklist, for downstream type propagation
  void ReplaceAllUses(llvm::Value *orig_inst, llvm::Value *new_inst);

  // We need to get a pointer from some value
  llvm::Value *getPointerToValue(llvm::IRBuilder<> &ir, llvm::Value *curr_val,
                                 llvm::Type *dest_type);

  // These visitor methods indicate that we know about pointer information to propagate
  // Some are maybes, because not all cast instructions are casts to pointers.
  std::pair<llvm::Value*, bool> visitIntToPtrInst(llvm::IntToPtrInst &inst);
  std::pair<llvm::Value*, bool> visitLoadInst(llvm::LoadInst &inst);
  //std::pair<llvm::Value*, bool>visitPtrToIntInst(llvm::PtrToIntInst &inst);
  std::pair<llvm::Value*, bool> visitGetElementPtrInst(llvm::GetElementPtrInst &inst);
  std::pair<llvm::Value*, bool> visitBitCastInst(llvm::BitCastInst &inst);
  //std::pair<llvm::Value*, bool>visitCastInst(llvm::CastInst &inst);
  // Simple wrapper for storing the type information into the list, and then calling visit.
  std::pair<llvm::Value*, bool> visitInferInst(llvm::Instruction *inst,
                              llvm::Type *inferred_type);
  std::pair<llvm::Value*, bool> visitInstruction(llvm::Instruction &I);
  std::pair<llvm::Value*, bool> visitBinaryOperator(llvm::BinaryOperator &inst);

  llvm::Value* GetIndexedPointer(llvm::IRBuilder<>& ir, llvm::Value *address, llvm::Value *offset, llvm::Type* t);
  // Driver method
  void LiftFunction(llvm::Function *func);

  /*
        // TODO (Carson)
        if you see an intoptr on a load, then you'll want to rewrite the load to be a load on a bitcast
        i.e. to load a pointer from mrmory, rather than an int
  */

 private:
  std::unordered_map<llvm::Value *, llvm::Type *> inferred_types;
  std::vector<llvm::Instruction *> next_worklist;
  std::unordered_set<llvm::Instruction*> to_remove;
  std::vector<std::pair<llvm::Instruction*, llvm::Value*>> to_replace;
  llvm::Module &module;
};

};  // namespace anvill

#endif